rule TTP_XOR_WriteProcessMemory_35d2 {
  strings:
    $key_35d2 = { 62 a0 [2] 50 82 [2] 56 b7 [2] 78 b7 [2] 47 ab }

  condition:
    any of them
}