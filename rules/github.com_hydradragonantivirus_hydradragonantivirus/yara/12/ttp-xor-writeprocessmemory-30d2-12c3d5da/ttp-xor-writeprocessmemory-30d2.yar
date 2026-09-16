rule TTP_XOR_WriteProcessMemory_30d2 {
  strings:
    $key_30d2 = { 67 a0 [2] 55 82 [2] 53 b7 [2] 7d b7 [2] 42 ab }

  condition:
    any of them
}