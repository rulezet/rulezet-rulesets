rule TTP_XOR_WriteProcessMemory_8cf2 {
  strings:
    $key_8cf2 = { db 80 [2] e9 a2 [2] ef 97 [2] c1 97 [2] fe 8b }

  condition:
    any of them
}