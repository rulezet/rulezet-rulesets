rule TTP_XOR_WriteProcessMemory_8c16 {
  strings:
    $key_8c16 = { db 64 [2] e9 46 [2] ef 73 [2] c1 73 [2] fe 6f }

  condition:
    any of them
}