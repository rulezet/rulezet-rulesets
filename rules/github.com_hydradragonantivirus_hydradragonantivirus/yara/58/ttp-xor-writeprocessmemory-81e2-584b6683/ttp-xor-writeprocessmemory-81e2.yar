rule TTP_XOR_WriteProcessMemory_81e2 {
  strings:
    $key_81e2 = { d6 90 [2] e4 b2 [2] e2 87 [2] cc 87 [2] f3 9b }

  condition:
    any of them
}