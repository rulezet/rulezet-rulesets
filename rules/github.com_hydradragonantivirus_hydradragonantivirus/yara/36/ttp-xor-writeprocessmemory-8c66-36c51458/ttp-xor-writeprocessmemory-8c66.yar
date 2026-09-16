rule TTP_XOR_WriteProcessMemory_8c66 {
  strings:
    $key_8c66 = { db 14 [2] e9 36 [2] ef 03 [2] c1 03 [2] fe 1f }

  condition:
    any of them
}