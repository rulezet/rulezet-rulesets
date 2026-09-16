rule TTP_XOR_WriteProcessMemory_62b7 {
  strings:
    $key_62b7 = { 35 c5 [2] 07 e7 [2] 01 d2 [2] 2f d2 [2] 10 ce }

  condition:
    any of them
}