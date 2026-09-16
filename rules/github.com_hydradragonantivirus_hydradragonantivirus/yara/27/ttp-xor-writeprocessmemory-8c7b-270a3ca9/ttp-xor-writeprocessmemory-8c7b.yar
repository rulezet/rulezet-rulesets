rule TTP_XOR_WriteProcessMemory_8c7b {
  strings:
    $key_8c7b = { db 09 [2] e9 2b [2] ef 1e [2] c1 1e [2] fe 02 }

  condition:
    any of them
}