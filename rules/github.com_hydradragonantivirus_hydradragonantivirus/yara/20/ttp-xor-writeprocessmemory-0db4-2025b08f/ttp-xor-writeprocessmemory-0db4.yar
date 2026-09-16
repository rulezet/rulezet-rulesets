rule TTP_XOR_WriteProcessMemory_0db4 {
  strings:
    $key_0db4 = { 5a c6 [2] 68 e4 [2] 6e d1 [2] 40 d1 [2] 7f cd }

  condition:
    any of them
}