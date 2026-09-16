rule TTP_XOR_WriteProcessMemory_8c6c {
  strings:
    $key_8c6c = { db 1e [2] e9 3c [2] ef 09 [2] c1 09 [2] fe 15 }

  condition:
    any of them
}