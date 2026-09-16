rule TTP_XOR_WriteProcessMemory_77d2 {
  strings:
    $key_77d2 = { 20 a0 [2] 12 82 [2] 14 b7 [2] 3a b7 [2] 05 ab }

  condition:
    any of them
}