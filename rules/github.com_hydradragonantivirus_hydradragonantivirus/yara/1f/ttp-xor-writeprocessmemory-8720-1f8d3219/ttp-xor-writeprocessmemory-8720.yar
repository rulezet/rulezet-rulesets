rule TTP_XOR_WriteProcessMemory_8720 {
  strings:
    $key_8720 = { d0 52 [2] e2 70 [2] e4 45 [2] ca 45 [2] f5 59 }

  condition:
    any of them
}