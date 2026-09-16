rule TTP_XOR_WriteProcessMemory_8cf5 {
  strings:
    $key_8cf5 = { db 87 [2] e9 a5 [2] ef 90 [2] c1 90 [2] fe 8c }

  condition:
    any of them
}