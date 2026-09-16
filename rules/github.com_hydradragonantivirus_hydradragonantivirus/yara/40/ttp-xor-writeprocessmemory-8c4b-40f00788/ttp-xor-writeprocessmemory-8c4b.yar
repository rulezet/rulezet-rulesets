rule TTP_XOR_WriteProcessMemory_8c4b {
  strings:
    $key_8c4b = { db 39 [2] e9 1b [2] ef 2e [2] c1 2e [2] fe 32 }

  condition:
    any of them
}