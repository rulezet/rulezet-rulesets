rule TTP_XOR_WriteProcessMemory_57d1 {
  strings:
    $key_57d1 = { 00 a3 [2] 32 81 [2] 34 b4 [2] 1a b4 [2] 25 a8 }

  condition:
    any of them
}