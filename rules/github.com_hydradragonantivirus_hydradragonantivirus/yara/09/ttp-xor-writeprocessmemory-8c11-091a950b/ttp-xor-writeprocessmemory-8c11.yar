rule TTP_XOR_WriteProcessMemory_8c11 {
  strings:
    $key_8c11 = { db 63 [2] e9 41 [2] ef 74 [2] c1 74 [2] fe 68 }

  condition:
    any of them
}