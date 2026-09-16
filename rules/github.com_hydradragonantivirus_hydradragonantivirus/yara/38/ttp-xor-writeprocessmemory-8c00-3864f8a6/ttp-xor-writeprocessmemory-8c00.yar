rule TTP_XOR_WriteProcessMemory_8c00 {
  strings:
    $key_8c00 = { db 72 [2] e9 50 [2] ef 65 [2] c1 65 [2] fe 79 }

  condition:
    any of them
}