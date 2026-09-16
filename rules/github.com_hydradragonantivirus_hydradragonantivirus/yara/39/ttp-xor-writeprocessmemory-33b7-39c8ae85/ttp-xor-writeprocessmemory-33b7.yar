rule TTP_XOR_WriteProcessMemory_33b7 {
  strings:
    $key_33b7 = { 64 c5 [2] 56 e7 [2] 50 d2 [2] 7e d2 [2] 41 ce }

  condition:
    any of them
}