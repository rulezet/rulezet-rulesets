rule TTP_XOR_WriteProcessMemory_b604 {
  strings:
    $key_b604 = { e1 76 [2] d3 54 [2] d5 61 [2] fb 61 [2] c4 7d }

  condition:
    any of them
}