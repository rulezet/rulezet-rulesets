rule TTP_XOR_WriteProcessMemory_8ce8 {
  strings:
    $key_8ce8 = { db 9a [2] e9 b8 [2] ef 8d [2] c1 8d [2] fe 91 }

  condition:
    any of them
}