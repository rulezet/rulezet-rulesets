rule TTP_XOR_WriteProcessMemory_8c08 {
  strings:
    $key_8c08 = { db 7a [2] e9 58 [2] ef 6d [2] c1 6d [2] fe 71 }

  condition:
    any of them
}