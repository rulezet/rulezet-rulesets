rule TTP_XOR_WriteProcessMemory_70b7 {
  strings:
    $key_70b7 = { 27 c5 [2] 15 e7 [2] 13 d2 [2] 3d d2 [2] 02 ce }

  condition:
    any of them
}