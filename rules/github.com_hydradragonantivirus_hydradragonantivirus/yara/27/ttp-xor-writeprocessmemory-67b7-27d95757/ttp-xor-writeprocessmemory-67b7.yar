rule TTP_XOR_WriteProcessMemory_67b7 {
  strings:
    $key_67b7 = { 30 c5 [2] 02 e7 [2] 04 d2 [2] 2a d2 [2] 15 ce }

  condition:
    any of them
}