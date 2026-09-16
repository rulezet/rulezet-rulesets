rule TTP_XOR_WriteProcessMemory_8c25 {
  strings:
    $key_8c25 = { db 57 [2] e9 75 [2] ef 40 [2] c1 40 [2] fe 5c }

  condition:
    any of them
}