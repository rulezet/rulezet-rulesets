rule TTP_XOR_WriteProcessMemory_8c45 {
  strings:
    $key_8c45 = { db 37 [2] e9 15 [2] ef 20 [2] c1 20 [2] fe 3c }

  condition:
    any of them
}