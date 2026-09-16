rule TTP_XOR_WriteProcessMemory_8c75 {
  strings:
    $key_8c75 = { db 07 [2] e9 25 [2] ef 10 [2] c1 10 [2] fe 0c }

  condition:
    any of them
}