rule TTP_XOR_WriteProcessMemory_8c74 {
  strings:
    $key_8c74 = { db 06 [2] e9 24 [2] ef 11 [2] c1 11 [2] fe 0d }

  condition:
    any of them
}