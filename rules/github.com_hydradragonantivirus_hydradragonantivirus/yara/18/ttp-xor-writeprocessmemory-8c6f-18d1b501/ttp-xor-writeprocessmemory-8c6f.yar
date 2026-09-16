rule TTP_XOR_WriteProcessMemory_8c6f {
  strings:
    $key_8c6f = { db 1d [2] e9 3f [2] ef 0a [2] c1 0a [2] fe 16 }

  condition:
    any of them
}