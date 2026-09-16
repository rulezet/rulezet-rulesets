rule TTP_XOR_WriteProcessMemory_8cf3 {
  strings:
    $key_8cf3 = { db 81 [2] e9 a3 [2] ef 96 [2] c1 96 [2] fe 8a }

  condition:
    any of them
}