rule TTP_XOR_WriteProcessMemory_8c5a {
  strings:
    $key_8c5a = { db 28 [2] e9 0a [2] ef 3f [2] c1 3f [2] fe 23 }

  condition:
    any of them
}