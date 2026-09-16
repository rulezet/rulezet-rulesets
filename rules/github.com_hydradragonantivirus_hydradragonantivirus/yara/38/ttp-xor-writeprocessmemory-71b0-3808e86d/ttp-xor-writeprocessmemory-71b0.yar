rule TTP_XOR_WriteProcessMemory_71b0 {
  strings:
    $key_71b0 = { 26 c2 [2] 14 e0 [2] 12 d5 [2] 3c d5 [2] 03 c9 }

  condition:
    any of them
}