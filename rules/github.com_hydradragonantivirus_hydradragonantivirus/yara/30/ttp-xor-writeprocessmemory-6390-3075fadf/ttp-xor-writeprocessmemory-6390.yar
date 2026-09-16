rule TTP_XOR_WriteProcessMemory_6390 {
  strings:
    $key_6390 = { 34 e2 [2] 06 c0 [2] 00 f5 [2] 2e f5 [2] 11 e9 }

  condition:
    any of them
}