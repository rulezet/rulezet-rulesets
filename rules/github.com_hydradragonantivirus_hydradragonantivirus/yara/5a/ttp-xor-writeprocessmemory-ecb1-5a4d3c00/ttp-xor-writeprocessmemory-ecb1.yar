rule TTP_XOR_WriteProcessMemory_ecb1 {
  strings:
    $key_ecb1 = { bb c3 [2] 89 e1 [2] 8f d4 [2] a1 d4 [2] 9e c8 }

  condition:
    any of them
}