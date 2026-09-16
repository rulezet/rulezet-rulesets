rule TTP_XOR_WriteProcessMemory_8cb2 {
  strings:
    $key_8cb2 = { db c0 [2] e9 e2 [2] ef d7 [2] c1 d7 [2] fe cb }

  condition:
    any of them
}