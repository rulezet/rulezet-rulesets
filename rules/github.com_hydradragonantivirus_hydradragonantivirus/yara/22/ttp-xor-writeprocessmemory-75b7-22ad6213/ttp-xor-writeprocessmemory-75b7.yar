rule TTP_XOR_WriteProcessMemory_75b7 {
  strings:
    $key_75b7 = { 22 c5 [2] 10 e7 [2] 16 d2 [2] 38 d2 [2] 07 ce }

  condition:
    any of them
}