rule TTP_XOR_WriteProcessMemory_8c73 {
  strings:
    $key_8c73 = { db 01 [2] e9 23 [2] ef 16 [2] c1 16 [2] fe 0a }

  condition:
    any of them
}