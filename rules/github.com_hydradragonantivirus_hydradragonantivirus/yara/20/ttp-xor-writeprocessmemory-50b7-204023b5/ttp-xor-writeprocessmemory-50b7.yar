rule TTP_XOR_WriteProcessMemory_50b7 {
  strings:
    $key_50b7 = { 07 c5 [2] 35 e7 [2] 33 d2 [2] 1d d2 [2] 22 ce }

  condition:
    any of them
}