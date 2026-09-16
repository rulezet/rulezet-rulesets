rule TTP_XOR_WriteProcessMemory_8c3f {
  strings:
    $key_8c3f = { db 4d [2] e9 6f [2] ef 5a [2] c1 5a [2] fe 46 }

  condition:
    any of them
}