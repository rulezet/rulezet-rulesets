rule TTP_XOR_WriteProcessMemory_8cfc {
  strings:
    $key_8cfc = { db 8e [2] e9 ac [2] ef 99 [2] c1 99 [2] fe 85 }

  condition:
    any of them
}