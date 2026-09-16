rule TTP_XOR_WriteProcessMemory_6cb7 {
  strings:
    $key_6cb7 = { 3b c5 [2] 09 e7 [2] 0f d2 [2] 21 d2 [2] 1e ce }

  condition:
    any of them
}