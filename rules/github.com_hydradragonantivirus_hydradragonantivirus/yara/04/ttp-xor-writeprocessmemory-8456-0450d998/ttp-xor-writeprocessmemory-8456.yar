rule TTP_XOR_WriteProcessMemory_8456 {
  strings:
    $key_8456 = { d3 24 [2] e1 06 [2] e7 33 [2] c9 33 [2] f6 2f }

  condition:
    any of them
}