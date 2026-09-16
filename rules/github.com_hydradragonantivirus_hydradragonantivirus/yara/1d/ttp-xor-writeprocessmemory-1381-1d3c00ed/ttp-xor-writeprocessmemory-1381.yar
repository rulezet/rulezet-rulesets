rule TTP_XOR_WriteProcessMemory_1381 {
  strings:
    $key_1381 = { 44 f3 [2] 76 d1 [2] 70 e4 [2] 5e e4 [2] 61 f8 }

  condition:
    any of them
}