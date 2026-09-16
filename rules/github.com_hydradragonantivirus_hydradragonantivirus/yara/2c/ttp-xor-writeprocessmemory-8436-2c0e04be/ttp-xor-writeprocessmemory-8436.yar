rule TTP_XOR_WriteProcessMemory_8436 {
  strings:
    $key_8436 = { d3 44 [2] e1 66 [2] e7 53 [2] c9 53 [2] f6 4f }

  condition:
    any of them
}