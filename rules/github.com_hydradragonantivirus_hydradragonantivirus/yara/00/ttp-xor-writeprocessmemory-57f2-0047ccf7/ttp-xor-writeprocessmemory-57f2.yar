rule TTP_XOR_WriteProcessMemory_57f2 {
  strings:
    $key_57f2 = { 00 80 [2] 32 a2 [2] 34 97 [2] 1a 97 [2] 25 8b }

  condition:
    any of them
}