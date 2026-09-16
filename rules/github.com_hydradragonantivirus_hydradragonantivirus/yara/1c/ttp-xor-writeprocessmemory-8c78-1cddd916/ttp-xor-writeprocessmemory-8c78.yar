rule TTP_XOR_WriteProcessMemory_8c78 {
  strings:
    $key_8c78 = { db 0a [2] e9 28 [2] ef 1d [2] c1 1d [2] fe 01 }

  condition:
    any of them
}