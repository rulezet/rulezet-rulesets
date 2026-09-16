rule TTP_XOR_WriteProcessMemory_8c20 {
  strings:
    $key_8c20 = { db 52 [2] e9 70 [2] ef 45 [2] c1 45 [2] fe 59 }

  condition:
    any of them
}