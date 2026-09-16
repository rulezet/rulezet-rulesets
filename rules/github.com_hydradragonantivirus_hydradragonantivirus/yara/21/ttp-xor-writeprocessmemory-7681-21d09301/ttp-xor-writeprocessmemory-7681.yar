rule TTP_XOR_WriteProcessMemory_7681 {
  strings:
    $key_7681 = { 21 f3 [2] 13 d1 [2] 15 e4 [2] 3b e4 [2] 04 f8 }

  condition:
    any of them
}