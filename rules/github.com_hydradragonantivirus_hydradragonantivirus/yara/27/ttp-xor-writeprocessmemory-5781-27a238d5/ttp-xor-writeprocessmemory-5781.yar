rule TTP_XOR_WriteProcessMemory_5781 {
  strings:
    $key_5781 = { 00 f3 [2] 32 d1 [2] 34 e4 [2] 1a e4 [2] 25 f8 }

  condition:
    any of them
}