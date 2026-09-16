rule TTP_XOR_WriteProcessMemory_8c1d {
  strings:
    $key_8c1d = { db 6f [2] e9 4d [2] ef 78 [2] c1 78 [2] fe 64 }

  condition:
    any of them
}