rule TTP_XOR_WriteProcessMemory_8c30 {
  strings:
    $key_8c30 = { db 42 [2] e9 60 [2] ef 55 [2] c1 55 [2] fe 49 }

  condition:
    any of them
}