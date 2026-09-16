rule TTP_XOR_WriteProcessMemory_8ce0 {
  strings:
    $key_8ce0 = { db 92 [2] e9 b0 [2] ef 85 [2] c1 85 [2] fe 99 }

  condition:
    any of them
}