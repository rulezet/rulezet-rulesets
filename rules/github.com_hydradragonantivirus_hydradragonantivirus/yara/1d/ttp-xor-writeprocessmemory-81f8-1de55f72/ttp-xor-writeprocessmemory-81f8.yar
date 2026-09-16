rule TTP_XOR_WriteProcessMemory_81f8 {
  strings:
    $key_81f8 = { d6 8a [2] e4 a8 [2] e2 9d [2] cc 9d [2] f3 81 }

  condition:
    any of them
}