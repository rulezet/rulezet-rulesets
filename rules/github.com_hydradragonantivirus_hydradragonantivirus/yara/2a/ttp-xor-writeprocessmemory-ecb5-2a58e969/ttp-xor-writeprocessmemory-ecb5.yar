rule TTP_XOR_WriteProcessMemory_ecb5 {
  strings:
    $key_ecb5 = { bb c7 [2] 89 e5 [2] 8f d0 [2] a1 d0 [2] 9e cc }

  condition:
    any of them
}