rule TTP_XOR_WriteProcessMemory_8c49 {
  strings:
    $key_8c49 = { db 3b [2] e9 19 [2] ef 2c [2] c1 2c [2] fe 30 }

  condition:
    any of them
}