rule TTP_XOR_WriteProcessMemory_8c2a {
  strings:
    $key_8c2a = { db 58 [2] e9 7a [2] ef 4f [2] c1 4f [2] fe 53 }

  condition:
    any of them
}