rule TTP_XOR_WriteProcessMemory_77b7 {
  strings:
    $key_77b7 = { 20 c5 [2] 12 e7 [2] 14 d2 [2] 3a d2 [2] 05 ce }

  condition:
    any of them
}