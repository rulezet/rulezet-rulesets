rule TTP_XOR_WriteProcessMemory_4db4 {
  strings:
    $key_4db4 = { 1a c6 [2] 28 e4 [2] 2e d1 [2] 00 d1 [2] 3f cd }

  condition:
    any of them
}