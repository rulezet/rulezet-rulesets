rule TTP_XOR_WriteProcessMemory_d6b7 {
  strings:
    $key_d6b7 = { 81 c5 [2] b3 e7 [2] b5 d2 [2] 9b d2 [2] a4 ce }

  condition:
    any of them
}