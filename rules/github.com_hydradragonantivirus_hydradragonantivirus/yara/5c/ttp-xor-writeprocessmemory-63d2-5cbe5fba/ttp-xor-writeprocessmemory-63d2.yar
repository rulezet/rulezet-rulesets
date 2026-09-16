rule TTP_XOR_WriteProcessMemory_63d2 {
  strings:
    $key_63d2 = { 34 a0 [2] 06 82 [2] 00 b7 [2] 2e b7 [2] 11 ab }

  condition:
    any of them
}