rule TTP_XOR_WriteProcessMemory_8c34 {
  strings:
    $key_8c34 = { db 46 [2] e9 64 [2] ef 51 [2] c1 51 [2] fe 4d }

  condition:
    any of them
}