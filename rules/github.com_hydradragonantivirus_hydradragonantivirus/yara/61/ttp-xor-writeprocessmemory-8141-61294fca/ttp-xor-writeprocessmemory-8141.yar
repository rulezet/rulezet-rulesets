rule TTP_XOR_WriteProcessMemory_8141 {
  strings:
    $key_8141 = { d6 33 [2] e4 11 [2] e2 24 [2] cc 24 [2] f3 38 }

  condition:
    any of them
}