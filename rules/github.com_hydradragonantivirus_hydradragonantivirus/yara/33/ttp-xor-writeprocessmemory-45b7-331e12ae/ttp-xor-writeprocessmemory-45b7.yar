rule TTP_XOR_WriteProcessMemory_45b7 {
  strings:
    $key_45b7 = { 12 c5 [2] 20 e7 [2] 26 d2 [2] 08 d2 [2] 37 ce }

  condition:
    any of them
}