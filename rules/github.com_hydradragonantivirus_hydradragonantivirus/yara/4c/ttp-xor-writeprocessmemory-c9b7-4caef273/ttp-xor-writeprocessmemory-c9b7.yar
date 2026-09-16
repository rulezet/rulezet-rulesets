rule TTP_XOR_WriteProcessMemory_c9b7 {
  strings:
    $key_c9b7 = { 9e c5 [2] ac e7 [2] aa d2 [2] 84 d2 [2] bb ce }

  condition:
    any of them
}