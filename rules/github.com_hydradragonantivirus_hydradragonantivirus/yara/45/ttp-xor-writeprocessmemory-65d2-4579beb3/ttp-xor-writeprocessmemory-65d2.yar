rule TTP_XOR_WriteProcessMemory_65d2 {
  strings:
    $key_65d2 = { 32 a0 [2] 00 82 [2] 06 b7 [2] 28 b7 [2] 17 ab }

  condition:
    any of them
}