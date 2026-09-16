rule TTP_XOR_WriteProcessMemory_81f2 {
  strings:
    $key_81f2 = { d6 80 [2] e4 a2 [2] e2 97 [2] cc 97 [2] f3 8b }

  condition:
    any of them
}