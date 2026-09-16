rule TTP_XOR_WriteProcessMemory_73b7 {
  strings:
    $key_73b7 = { 24 c5 [2] 16 e7 [2] 10 d2 [2] 3e d2 [2] 01 ce }

  condition:
    any of them
}