rule TTP_XOR_WriteProcessMemory_13b7 {
  strings:
    $key_13b7 = { 44 c5 [2] 76 e7 [2] 70 d2 [2] 5e d2 [2] 61 ce }

  condition:
    any of them
}