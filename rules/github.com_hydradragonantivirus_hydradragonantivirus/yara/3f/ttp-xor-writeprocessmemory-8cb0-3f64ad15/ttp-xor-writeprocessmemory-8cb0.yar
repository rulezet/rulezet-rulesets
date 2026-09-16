rule TTP_XOR_WriteProcessMemory_8cb0 {
  strings:
    $key_8cb0 = { db c2 [2] e9 e0 [2] ef d5 [2] c1 d5 [2] fe c9 }

  condition:
    any of them
}