rule TTP_XOR_WriteProcessMemory_57a1 {
  strings:
    $key_57a1 = { 00 d3 [2] 32 f1 [2] 34 c4 [2] 1a c4 [2] 25 d8 }

  condition:
    any of them
}