rule TTP_XOR_WriteProcessMemory_68b0 {
  strings:
    $key_68b0 = { 3f c2 [2] 0d e0 [2] 0b d5 [2] 25 d5 [2] 1a c9 }

  condition:
    any of them
}