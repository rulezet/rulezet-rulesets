rule TTP_XOR_WriteProcessMemory_1db4 {
  strings:
    $key_1db4 = { 4a c6 [2] 78 e4 [2] 7e d1 [2] 50 d1 [2] 6f cd }

  condition:
    any of them
}