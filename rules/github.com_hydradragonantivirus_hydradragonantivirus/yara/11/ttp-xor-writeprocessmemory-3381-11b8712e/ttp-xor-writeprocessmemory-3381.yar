rule TTP_XOR_WriteProcessMemory_3381 {
  strings:
    $key_3381 = { 64 f3 [2] 56 d1 [2] 50 e4 [2] 7e e4 [2] 41 f8 }

  condition:
    any of them
}