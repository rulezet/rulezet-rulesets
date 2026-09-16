rule TTP_XOR_WriteProcessMemory_6db1 {
  strings:
    $key_6db1 = { 3a c3 [2] 08 e1 [2] 0e d4 [2] 20 d4 [2] 1f c8 }

  condition:
    any of them
}