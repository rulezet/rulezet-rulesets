rule TTP_XOR_WriteProcessMemory_8cf4 {
  strings:
    $key_8cf4 = { db 86 [2] e9 a4 [2] ef 91 [2] c1 91 [2] fe 8d }

  condition:
    any of them
}