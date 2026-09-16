rule TTP_XOR_WriteProcessMemory_8ced {
  strings:
    $key_8ced = { db 9f [2] e9 bd [2] ef 88 [2] c1 88 [2] fe 94 }

  condition:
    any of them
}