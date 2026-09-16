rule TTP_XOR_WriteProcessMemory_8ce9 {
  strings:
    $key_8ce9 = { db 9b [2] e9 b9 [2] ef 8c [2] c1 8c [2] fe 90 }

  condition:
    any of them
}