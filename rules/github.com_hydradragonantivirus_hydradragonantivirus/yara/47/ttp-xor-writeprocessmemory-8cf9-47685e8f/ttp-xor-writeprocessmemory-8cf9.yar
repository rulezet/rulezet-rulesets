rule TTP_XOR_WriteProcessMemory_8cf9 {
  strings:
    $key_8cf9 = { db 8b [2] e9 a9 [2] ef 9c [2] c1 9c [2] fe 80 }

  condition:
    any of them
}