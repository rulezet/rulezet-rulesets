rule TTP_XOR_WriteProcessMemory_8cfd {
  strings:
    $key_8cfd = { db 8f [2] e9 ad [2] ef 98 [2] c1 98 [2] fe 84 }

  condition:
    any of them
}