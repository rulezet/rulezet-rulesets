rule TTP_XOR_WriteProcessMemory_b656 {
  strings:
    $key_b656 = { e1 24 [2] d3 06 [2] d5 33 [2] fb 33 [2] c4 2f }

  condition:
    any of them
}