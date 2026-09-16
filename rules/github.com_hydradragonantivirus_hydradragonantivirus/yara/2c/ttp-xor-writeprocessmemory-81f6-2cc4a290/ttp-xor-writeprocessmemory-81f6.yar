rule TTP_XOR_WriteProcessMemory_81f6 {
  strings:
    $key_81f6 = { d6 84 [2] e4 a6 [2] e2 93 [2] cc 93 [2] f3 8f }

  condition:
    any of them
}