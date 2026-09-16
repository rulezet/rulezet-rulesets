rule TTP_XOR_WriteProcessMemory_8463 {
  strings:
    $key_8463 = { d3 11 [2] e1 33 [2] e7 06 [2] c9 06 [2] f6 1a }

  condition:
    any of them
}