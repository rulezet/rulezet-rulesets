rule TTP_XOR_WriteProcessMemory_8ce6 {
  strings:
    $key_8ce6 = { db 94 [2] e9 b6 [2] ef 83 [2] c1 83 [2] fe 9f }

  condition:
    any of them
}