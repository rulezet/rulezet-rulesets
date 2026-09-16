rule TTP_XOR_WriteProcessMemory_8cfb {
  strings:
    $key_8cfb = { db 89 [2] e9 ab [2] ef 9e [2] c1 9e [2] fe 82 }

  condition:
    any of them
}