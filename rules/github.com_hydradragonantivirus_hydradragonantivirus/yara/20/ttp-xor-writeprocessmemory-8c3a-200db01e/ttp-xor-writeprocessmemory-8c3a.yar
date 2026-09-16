rule TTP_XOR_WriteProcessMemory_8c3a {
  strings:
    $key_8c3a = { db 48 [2] e9 6a [2] ef 5f [2] c1 5f [2] fe 43 }

  condition:
    any of them
}