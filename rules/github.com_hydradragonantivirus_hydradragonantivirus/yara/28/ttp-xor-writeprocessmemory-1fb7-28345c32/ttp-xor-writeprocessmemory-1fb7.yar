rule TTP_XOR_WriteProcessMemory_1fb7 {
  strings:
    $key_1fb7 = { 48 c5 [2] 7a e7 [2] 7c d2 [2] 52 d2 [2] 6d ce }

  condition:
    any of them
}