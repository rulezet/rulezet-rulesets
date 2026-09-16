rule TTP_XOR_WriteProcessMemory_8c1f {
  strings:
    $key_8c1f = { db 6d [2] e9 4f [2] ef 7a [2] c1 7a [2] fe 66 }

  condition:
    any of them
}