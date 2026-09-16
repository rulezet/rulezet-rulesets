rule TTP_XOR_WriteProcessMemory_8c43 {
  strings:
    $key_8c43 = { db 31 [2] e9 13 [2] ef 26 [2] c1 26 [2] fe 3a }

  condition:
    any of them
}