rule TTP_XOR_WriteProcessMemory_1db1 {
  strings:
    $key_1db1 = { 4a c3 [2] 78 e1 [2] 7e d4 [2] 50 d4 [2] 6f c8 }

  condition:
    any of them
}