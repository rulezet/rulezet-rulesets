rule TTP_XOR_WriteProcessMemory_0cb7 {
  strings:
    $key_0cb7 = { 5b c5 [2] 69 e7 [2] 6f d2 [2] 41 d2 [2] 7e ce }

  condition:
    any of them
}