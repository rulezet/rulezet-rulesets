rule TTP_XOR_WriteProcessMemory_8c46 {
  strings:
    $key_8c46 = { db 34 [2] e9 16 [2] ef 23 [2] c1 23 [2] fe 3f }

  condition:
    any of them
}