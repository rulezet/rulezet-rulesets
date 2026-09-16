rule TTP_XOR_WriteProcessMemory_57f0 {
  strings:
    $key_57f0 = { 00 82 [2] 32 a0 [2] 34 95 [2] 1a 95 [2] 25 89 }

  condition:
    any of them
}