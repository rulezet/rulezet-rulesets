rule TTP_XOR_WriteProcessMemory_8cb4 {
  strings:
    $key_8cb4 = { db c6 [2] e9 e4 [2] ef d1 [2] c1 d1 [2] fe cd }

  condition:
    any of them
}