rule TTP_XOR_WriteProcessMemory_15d2 {
  strings:
    $key_15d2 = { 42 a0 [2] 70 82 [2] 76 b7 [2] 58 b7 [2] 67 ab }

  condition:
    any of them
}