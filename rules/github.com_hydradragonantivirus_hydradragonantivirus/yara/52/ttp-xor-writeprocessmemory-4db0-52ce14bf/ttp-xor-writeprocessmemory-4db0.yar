rule TTP_XOR_WriteProcessMemory_4db0 {
  strings:
    $key_4db0 = { 1a c2 [2] 28 e0 [2] 2e d5 [2] 00 d5 [2] 3f c9 }

  condition:
    any of them
}