rule TTP_XOR_WriteProcessMemory_8c2e {
  strings:
    $key_8c2e = { db 5c [2] e9 7e [2] ef 4b [2] c1 4b [2] fe 57 }

  condition:
    any of them
}