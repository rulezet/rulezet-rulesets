rule TTP_XOR_WriteProcessMemory_8c23 {
  strings:
    $key_8c23 = { db 51 [2] e9 73 [2] ef 46 [2] c1 46 [2] fe 5a }

  condition:
    any of them
}