rule TTP_XOR_WriteProcessMemory_8c5d {
  strings:
    $key_8c5d = { db 2f [2] e9 0d [2] ef 38 [2] c1 38 [2] fe 24 }

  condition:
    any of them
}