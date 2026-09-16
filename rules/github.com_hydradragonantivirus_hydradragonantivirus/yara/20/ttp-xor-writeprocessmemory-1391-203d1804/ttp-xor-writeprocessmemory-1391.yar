rule TTP_XOR_WriteProcessMemory_1391 {
  strings:
    $key_1391 = { 44 e3 [2] 76 c1 [2] 70 f4 [2] 5e f4 [2] 61 e8 }

  condition:
    any of them
}