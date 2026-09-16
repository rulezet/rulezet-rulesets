rule TTP_XOR_WriteProcessMemory_3390 {
  strings:
    $key_3390 = { 64 e2 [2] 56 c0 [2] 50 f5 [2] 7e f5 [2] 41 e9 }

  condition:
    any of them
}