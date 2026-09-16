rule TTP_XOR_WriteProcessMemory_6db4 {
  strings:
    $key_6db4 = { 3a c6 [2] 08 e4 [2] 0e d1 [2] 20 d1 [2] 1f cd }

  condition:
    any of them
}