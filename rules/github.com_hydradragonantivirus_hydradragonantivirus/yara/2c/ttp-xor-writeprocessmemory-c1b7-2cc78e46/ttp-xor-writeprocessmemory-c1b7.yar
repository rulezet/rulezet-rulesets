rule TTP_XOR_WriteProcessMemory_c1b7 {
  strings:
    $key_c1b7 = { 96 c5 [2] a4 e7 [2] a2 d2 [2] 8c d2 [2] b3 ce }

  condition:
    any of them
}