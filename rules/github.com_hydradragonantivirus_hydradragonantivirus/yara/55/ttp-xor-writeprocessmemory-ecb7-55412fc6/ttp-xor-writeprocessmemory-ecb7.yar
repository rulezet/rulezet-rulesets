rule TTP_XOR_WriteProcessMemory_ecb7 {
  strings:
    $key_ecb7 = { bb c5 [2] 89 e7 [2] 8f d2 [2] a1 d2 [2] 9e ce }

  condition:
    any of them
}