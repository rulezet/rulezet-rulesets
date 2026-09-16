rule TTP_XOR_WriteProcessMemory_47b7 {
  strings:
    $key_47b7 = { 10 c5 [2] 22 e7 [2] 24 d2 [2] 0a d2 [2] 35 ce }

  condition:
    any of them
}