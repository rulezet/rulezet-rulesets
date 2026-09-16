rule TTP_XOR_WriteProcessMemory_8c3e {
  strings:
    $key_8c3e = { db 4c [2] e9 6e [2] ef 5b [2] c1 5b [2] fe 47 }

  condition:
    any of them
}