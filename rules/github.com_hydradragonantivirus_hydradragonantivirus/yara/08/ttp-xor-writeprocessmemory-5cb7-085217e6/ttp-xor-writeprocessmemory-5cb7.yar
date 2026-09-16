rule TTP_XOR_WriteProcessMemory_5cb7 {
  strings:
    $key_5cb7 = { 0b c5 [2] 39 e7 [2] 3f d2 [2] 11 d2 [2] 2e ce }

  condition:
    any of them
}