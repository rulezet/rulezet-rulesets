rule TTP_XOR_WriteProcessMemory_57f5 {
  strings:
    $key_57f5 = { 00 87 [2] 32 a5 [2] 34 90 [2] 1a 90 [2] 25 8c }

  condition:
    any of them
}