rule TTP_XOR_WriteProcessMemory_6fb7 {
  strings:
    $key_6fb7 = { 38 c5 [2] 0a e7 [2] 0c d2 [2] 22 d2 [2] 1d ce }

  condition:
    any of them
}