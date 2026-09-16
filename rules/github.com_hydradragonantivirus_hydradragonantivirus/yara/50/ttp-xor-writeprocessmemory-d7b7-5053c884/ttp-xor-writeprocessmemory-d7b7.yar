rule TTP_XOR_WriteProcessMemory_d7b7 {
  strings:
    $key_d7b7 = { 80 c5 [2] b2 e7 [2] b4 d2 [2] 9a d2 [2] a5 ce }

  condition:
    any of them
}