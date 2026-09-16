rule TTP_XOR_WriteProcessMemory_b670 {
  strings:
    $key_b670 = { e1 02 [2] d3 20 [2] d5 15 [2] fb 15 [2] c4 09 }

  condition:
    any of them
}