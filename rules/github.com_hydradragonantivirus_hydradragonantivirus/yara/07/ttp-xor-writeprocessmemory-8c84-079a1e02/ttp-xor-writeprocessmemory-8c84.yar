rule TTP_XOR_WriteProcessMemory_8c84 {
  strings:
    $key_8c84 = { db f6 [2] e9 d4 [2] ef e1 [2] c1 e1 [2] fe fd }

  condition:
    any of them
}