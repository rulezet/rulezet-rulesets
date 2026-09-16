rule TTP_XOR_WriteProcessMemory_8c2f {
  strings:
    $key_8c2f = { db 5d [2] e9 7f [2] ef 4a [2] c1 4a [2] fe 56 }

  condition:
    any of them
}