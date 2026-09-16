rule TTP_XOR_WriteProcessMemory_57d6 {
  strings:
    $key_57d6 = { 00 a4 [2] 32 86 [2] 34 b3 [2] 1a b3 [2] 25 af }

  condition:
    any of them
}