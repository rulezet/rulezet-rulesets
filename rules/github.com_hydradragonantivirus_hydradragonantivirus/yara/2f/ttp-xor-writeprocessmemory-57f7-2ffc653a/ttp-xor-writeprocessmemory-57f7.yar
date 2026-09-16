rule TTP_XOR_WriteProcessMemory_57f7 {
  strings:
    $key_57f7 = { 00 85 [2] 32 a7 [2] 34 92 [2] 1a 92 [2] 25 8e }

  condition:
    any of them
}