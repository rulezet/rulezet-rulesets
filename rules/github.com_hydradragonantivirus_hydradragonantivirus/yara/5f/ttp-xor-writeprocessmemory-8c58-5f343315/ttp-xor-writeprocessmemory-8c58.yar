rule TTP_XOR_WriteProcessMemory_8c58 {
  strings:
    $key_8c58 = { db 2a [2] e9 08 [2] ef 3d [2] c1 3d [2] fe 21 }

  condition:
    any of them
}