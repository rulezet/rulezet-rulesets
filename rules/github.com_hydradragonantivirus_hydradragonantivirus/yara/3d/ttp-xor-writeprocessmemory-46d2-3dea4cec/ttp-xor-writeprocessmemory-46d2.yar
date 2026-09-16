rule TTP_XOR_WriteProcessMemory_46d2 {
  strings:
    $key_46d2 = { 11 a0 [2] 23 82 [2] 25 b7 [2] 0b b7 [2] 34 ab }

  condition:
    any of them
}