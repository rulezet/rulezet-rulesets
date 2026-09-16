rule TTP_XOR_WriteProcessMemory_8c33 {
  strings:
    $key_8c33 = { db 41 [2] e9 63 [2] ef 56 [2] c1 56 [2] fe 4a }

  condition:
    any of them
}