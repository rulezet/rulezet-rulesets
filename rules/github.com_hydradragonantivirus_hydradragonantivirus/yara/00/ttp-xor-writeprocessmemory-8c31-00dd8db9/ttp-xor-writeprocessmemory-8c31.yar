rule TTP_XOR_WriteProcessMemory_8c31 {
  strings:
    $key_8c31 = { db 43 [2] e9 61 [2] ef 54 [2] c1 54 [2] fe 48 }

  condition:
    any of them
}