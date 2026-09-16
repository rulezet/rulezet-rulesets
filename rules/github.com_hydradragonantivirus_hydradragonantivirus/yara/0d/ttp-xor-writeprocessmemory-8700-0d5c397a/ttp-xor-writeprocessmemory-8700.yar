rule TTP_XOR_WriteProcessMemory_8700 {
  strings:
    $key_8700 = { d0 72 [2] e2 50 [2] e4 65 [2] ca 65 [2] f5 79 }

  condition:
    any of them
}