rule TTP_XOR_WriteProcessMemory_81f5 {
  strings:
    $key_81f5 = { d6 87 [2] e4 a5 [2] e2 90 [2] cc 90 [2] f3 8c }

  condition:
    any of them
}