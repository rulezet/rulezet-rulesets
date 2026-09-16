rule TTP_XOR_WriteProcessMemory_cab7 {
  strings:
    $key_cab7 = { 9d c5 [2] af e7 [2] a9 d2 [2] 87 d2 [2] b8 ce }

  condition:
    any of them
}