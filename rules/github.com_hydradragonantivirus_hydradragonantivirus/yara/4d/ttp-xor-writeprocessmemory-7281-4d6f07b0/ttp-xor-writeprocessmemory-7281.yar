rule TTP_XOR_WriteProcessMemory_7281 {
  strings:
    $key_7281 = { 25 f3 [2] 17 d1 [2] 11 e4 [2] 3f e4 [2] 00 f8 }

  condition:
    any of them
}