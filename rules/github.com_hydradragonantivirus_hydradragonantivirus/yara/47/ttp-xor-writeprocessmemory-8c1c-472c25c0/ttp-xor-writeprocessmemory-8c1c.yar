rule TTP_XOR_WriteProcessMemory_8c1c {
  strings:
    $key_8c1c = { db 6e [2] e9 4c [2] ef 79 [2] c1 79 [2] fe 65 }

  condition:
    any of them
}