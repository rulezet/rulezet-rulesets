rule TTP_XOR_WriteProcessMemory_57f3 {
  strings:
    $key_57f3 = { 00 81 [2] 32 a3 [2] 34 96 [2] 1a 96 [2] 25 8a }

  condition:
    any of them
}