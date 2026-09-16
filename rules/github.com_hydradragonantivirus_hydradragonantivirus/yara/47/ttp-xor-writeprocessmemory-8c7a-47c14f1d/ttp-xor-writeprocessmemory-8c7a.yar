rule TTP_XOR_WriteProcessMemory_8c7a {
  strings:
    $key_8c7a = { db 08 [2] e9 2a [2] ef 1f [2] c1 1f [2] fe 03 }

  condition:
    any of them
}