rule TTP_XOR_WriteProcessMemory_8c63 {
  strings:
    $key_8c63 = { db 11 [2] e9 33 [2] ef 06 [2] c1 06 [2] fe 1a }

  condition:
    any of them
}