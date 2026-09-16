rule TTP_XOR_WriteProcessMemory_8ce7 {
  strings:
    $key_8ce7 = { db 95 [2] e9 b7 [2] ef 82 [2] c1 82 [2] fe 9e }

  condition:
    any of them
}