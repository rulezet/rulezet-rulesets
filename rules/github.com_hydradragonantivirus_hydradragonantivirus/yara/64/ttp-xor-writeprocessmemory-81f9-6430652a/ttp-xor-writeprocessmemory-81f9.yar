rule TTP_XOR_WriteProcessMemory_81f9 {
  strings:
    $key_81f9 = { d6 8b [2] e4 a9 [2] e2 9c [2] cc 9c [2] f3 80 }

  condition:
    any of them
}