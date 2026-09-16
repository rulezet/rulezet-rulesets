rule TTP_XOR_WriteProcessMemory_2fb7 {
  strings:
    $key_2fb7 = { 78 c5 [2] 4a e7 [2] 4c d2 [2] 62 d2 [2] 5d ce }

  condition:
    any of them
}