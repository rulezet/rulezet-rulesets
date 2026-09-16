rule TTP_XOR_WriteProcessMemory_8c80 {
  strings:
    $key_8c80 = { db f2 [2] e9 d0 [2] ef e5 [2] c1 e5 [2] fe f9 }

  condition:
    any of them
}