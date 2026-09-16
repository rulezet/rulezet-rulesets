rule TTP_XOR_WriteProcessMemory_4481 {
  strings:
    $key_4481 = { 13 f3 [2] 21 d1 [2] 27 e4 [2] 09 e4 [2] 36 f8 }

  condition:
    any of them
}