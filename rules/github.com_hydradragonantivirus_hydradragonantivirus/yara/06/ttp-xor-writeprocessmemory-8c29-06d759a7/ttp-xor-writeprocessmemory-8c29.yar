rule TTP_XOR_WriteProcessMemory_8c29 {
  strings:
    $key_8c29 = { db 5b [2] e9 79 [2] ef 4c [2] c1 4c [2] fe 50 }

  condition:
    any of them
}