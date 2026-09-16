rule TTP_XOR_WriteProcessMemory_68b1 {
  strings:
    $key_68b1 = { 3f c3 [2] 0d e1 [2] 0b d4 [2] 25 d4 [2] 1a c8 }

  condition:
    any of them
}