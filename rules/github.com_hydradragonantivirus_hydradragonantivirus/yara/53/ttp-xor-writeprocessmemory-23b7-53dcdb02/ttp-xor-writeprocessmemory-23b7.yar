rule TTP_XOR_WriteProcessMemory_23b7 {
  strings:
    $key_23b7 = { 74 c5 [2] 46 e7 [2] 40 d2 [2] 6e d2 [2] 51 ce }

  condition:
    any of them
}