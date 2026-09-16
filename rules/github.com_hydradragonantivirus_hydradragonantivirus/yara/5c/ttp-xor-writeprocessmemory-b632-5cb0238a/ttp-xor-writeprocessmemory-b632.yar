rule TTP_XOR_WriteProcessMemory_b632 {
  strings:
    $key_b632 = { e1 40 [2] d3 62 [2] d5 57 [2] fb 57 [2] c4 4b }

  condition:
    any of them
}