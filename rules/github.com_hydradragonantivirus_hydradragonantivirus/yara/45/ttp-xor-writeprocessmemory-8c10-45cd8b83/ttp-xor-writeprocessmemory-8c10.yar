rule TTP_XOR_WriteProcessMemory_8c10 {
  strings:
    $key_8c10 = { db 62 [2] e9 40 [2] ef 75 [2] c1 75 [2] fe 69 }

  condition:
    any of them
}