rule TTP_XOR_WriteProcessMemory_1db2 {
  strings:
    $key_1db2 = { 4a c0 [2] 78 e2 [2] 7e d7 [2] 50 d7 [2] 6f cb }

  condition:
    any of them
}