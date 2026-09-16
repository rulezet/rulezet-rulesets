rule TTP_XOR_WriteProcessMemory_d1b7 {
  strings:
    $key_d1b7 = { 86 c5 [2] b4 e7 [2] b2 d2 [2] 9c d2 [2] a3 ce }

  condition:
    any of them
}