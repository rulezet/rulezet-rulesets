rule TTP_XOR_WriteProcessMemory_03b7 {
  strings:
    $key_03b7 = { 54 c5 [2] 66 e7 [2] 60 d2 [2] 4e d2 [2] 71 ce }

  condition:
    any of them
}