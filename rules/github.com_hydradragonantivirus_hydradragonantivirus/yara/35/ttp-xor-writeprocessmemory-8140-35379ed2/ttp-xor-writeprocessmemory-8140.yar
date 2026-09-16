rule TTP_XOR_WriteProcessMemory_8140 {
  strings:
    $key_8140 = { d6 32 [2] e4 10 [2] e2 25 [2] cc 25 [2] f3 39 }

  condition:
    any of them
}