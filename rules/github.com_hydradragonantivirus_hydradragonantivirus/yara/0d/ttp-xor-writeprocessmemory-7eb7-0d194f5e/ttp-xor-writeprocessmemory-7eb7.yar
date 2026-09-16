rule TTP_XOR_WriteProcessMemory_7eb7 {
  strings:
    $key_7eb7 = { 29 c5 [2] 1b e7 [2] 1d d2 [2] 33 d2 [2] 0c ce }

  condition:
    any of them
}