rule TTP_XOR_WriteProcessMemory_5db2 {
  strings:
    $key_5db2 = { 0a c0 [2] 38 e2 [2] 3e d7 [2] 10 d7 [2] 2f cb }

  condition:
    any of them
}