rule TTP_XOR_WriteProcessMemory_8c2b {
  strings:
    $key_8c2b = { db 59 [2] e9 7b [2] ef 4e [2] c1 4e [2] fe 52 }

  condition:
    any of them
}