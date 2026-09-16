rule TTP_XOR_WriteProcessMemory_67d2 {
  strings:
    $key_67d2 = { 30 a0 [2] 02 82 [2] 04 b7 [2] 2a b7 [2] 15 ab }

  condition:
    any of them
}