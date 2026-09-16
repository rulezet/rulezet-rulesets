rule TTP_XOR_WriteProcessMemory_b646 {
  strings:
    $key_b646 = { e1 34 [2] d3 16 [2] d5 23 [2] fb 23 [2] c4 3f }

  condition:
    any of them
}