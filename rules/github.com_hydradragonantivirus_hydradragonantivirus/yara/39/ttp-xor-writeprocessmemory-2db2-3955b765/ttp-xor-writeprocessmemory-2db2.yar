rule TTP_XOR_WriteProcessMemory_2db2 {
  strings:
    $key_2db2 = { 7a c0 [2] 48 e2 [2] 4e d7 [2] 60 d7 [2] 5f cb }

  condition:
    any of them
}