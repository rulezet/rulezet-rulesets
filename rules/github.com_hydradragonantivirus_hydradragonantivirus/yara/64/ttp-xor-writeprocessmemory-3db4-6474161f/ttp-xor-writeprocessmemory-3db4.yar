rule TTP_XOR_WriteProcessMemory_3db4 {
  strings:
    $key_3db4 = { 6a c6 [2] 58 e4 [2] 5e d1 [2] 70 d1 [2] 4f cd }

  condition:
    any of them
}