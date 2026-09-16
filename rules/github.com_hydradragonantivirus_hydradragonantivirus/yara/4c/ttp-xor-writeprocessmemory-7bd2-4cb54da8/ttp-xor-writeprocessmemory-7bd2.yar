rule TTP_XOR_WriteProcessMemory_7bd2 {
  strings:
    $key_7bd2 = { 2c a0 [2] 1e 82 [2] 18 b7 [2] 36 b7 [2] 09 ab }

  condition:
    any of them
}