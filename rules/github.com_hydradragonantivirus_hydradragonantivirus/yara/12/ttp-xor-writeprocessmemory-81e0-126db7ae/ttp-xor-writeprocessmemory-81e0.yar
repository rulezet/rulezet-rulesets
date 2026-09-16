rule TTP_XOR_WriteProcessMemory_81e0 {
  strings:
    $key_81e0 = { d6 92 [2] e4 b0 [2] e2 85 [2] cc 85 [2] f3 99 }

  condition:
    any of them
}