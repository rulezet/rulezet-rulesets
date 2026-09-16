rule TTP_XOR_WriteProcessMemory_ecba {
  strings:
    $key_ecba = { bb c8 [2] 89 ea [2] 8f df [2] a1 df [2] 9e c3 }

  condition:
    any of them
}