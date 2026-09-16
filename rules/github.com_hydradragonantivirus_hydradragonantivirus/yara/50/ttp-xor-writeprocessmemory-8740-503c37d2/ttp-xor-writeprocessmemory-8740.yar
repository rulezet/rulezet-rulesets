rule TTP_XOR_WriteProcessMemory_8740 {
  strings:
    $key_8740 = { d0 32 [2] e2 10 [2] e4 25 [2] ca 25 [2] f5 39 }

  condition:
    any of them
}