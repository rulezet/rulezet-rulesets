rule TTP_XOR_WriteProcessMemory_74d2 {
  strings:
    $key_74d2 = { 23 a0 [2] 11 82 [2] 17 b7 [2] 39 b7 [2] 06 ab }

  condition:
    any of them
}