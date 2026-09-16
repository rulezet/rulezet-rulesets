rule TTP_XOR_WriteProcessMemory_57d2 {
  strings:
    $key_57d2 = { 00 a0 [2] 32 82 [2] 34 b7 [2] 1a b7 [2] 25 ab }

  condition:
    any of them
}