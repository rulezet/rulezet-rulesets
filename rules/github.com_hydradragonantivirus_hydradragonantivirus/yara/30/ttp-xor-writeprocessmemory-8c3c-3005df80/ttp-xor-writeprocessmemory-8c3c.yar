rule TTP_XOR_WriteProcessMemory_8c3c {
  strings:
    $key_8c3c = { db 4e [2] e9 6c [2] ef 59 [2] c1 59 [2] fe 45 }

  condition:
    any of them
}