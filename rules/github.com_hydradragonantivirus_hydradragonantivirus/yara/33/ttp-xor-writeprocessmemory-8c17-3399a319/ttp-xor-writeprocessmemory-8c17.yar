rule TTP_XOR_WriteProcessMemory_8c17 {
  strings:
    $key_8c17 = { db 65 [2] e9 47 [2] ef 72 [2] c1 72 [2] fe 6e }

  condition:
    any of them
}