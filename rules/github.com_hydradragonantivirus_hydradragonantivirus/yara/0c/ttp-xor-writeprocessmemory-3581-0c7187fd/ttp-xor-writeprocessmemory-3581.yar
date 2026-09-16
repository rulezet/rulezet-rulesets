rule TTP_XOR_WriteProcessMemory_3581 {
  strings:
    $key_3581 = { 62 f3 [2] 50 d1 [2] 56 e4 [2] 78 e4 [2] 47 f8 }

  condition:
    any of them
}