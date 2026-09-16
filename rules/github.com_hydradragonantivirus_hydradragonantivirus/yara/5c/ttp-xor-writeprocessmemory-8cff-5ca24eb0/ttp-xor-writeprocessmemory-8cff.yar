rule TTP_XOR_WriteProcessMemory_8cff {
  strings:
    $key_8cff = { db 8d [2] e9 af [2] ef 9a [2] c1 9a [2] fe 86 }

  condition:
    any of them
}