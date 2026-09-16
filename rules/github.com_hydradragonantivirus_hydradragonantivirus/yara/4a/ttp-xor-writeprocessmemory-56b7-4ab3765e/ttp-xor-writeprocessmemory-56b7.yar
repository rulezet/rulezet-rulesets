rule TTP_XOR_WriteProcessMemory_56b7 {
  strings:
    $key_56b7 = { 01 c5 [2] 33 e7 [2] 35 d2 [2] 1b d2 [2] 24 ce }

  condition:
    any of them
}