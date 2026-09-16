rule TTP_XOR_WriteProcessMemory_1390 {
  strings:
    $key_1390 = { 44 e2 [2] 76 c0 [2] 70 f5 [2] 5e f5 [2] 61 e9 }

  condition:
    any of them
}