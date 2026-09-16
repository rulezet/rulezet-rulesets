rule TTP_XOR_WriteProcessMemory_1eb7 {
  strings:
    $key_1eb7 = { 49 c5 [2] 7b e7 [2] 7d d2 [2] 53 d2 [2] 6c ce }

  condition:
    any of them
}