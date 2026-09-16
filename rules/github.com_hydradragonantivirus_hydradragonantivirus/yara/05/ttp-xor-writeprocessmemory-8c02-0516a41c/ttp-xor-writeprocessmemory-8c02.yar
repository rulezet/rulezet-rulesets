rule TTP_XOR_WriteProcessMemory_8c02 {
  strings:
    $key_8c02 = { db 70 [2] e9 52 [2] ef 67 [2] c1 67 [2] fe 7b }

  condition:
    any of them
}