rule TTP_XOR_WriteProcessMemory_8c48 {
  strings:
    $key_8c48 = { db 3a [2] e9 18 [2] ef 2d [2] c1 2d [2] fe 31 }

  condition:
    any of them
}