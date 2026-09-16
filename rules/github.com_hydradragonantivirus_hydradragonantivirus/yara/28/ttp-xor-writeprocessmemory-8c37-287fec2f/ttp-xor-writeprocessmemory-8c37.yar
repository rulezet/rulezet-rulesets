rule TTP_XOR_WriteProcessMemory_8c37 {
  strings:
    $key_8c37 = { db 45 [2] e9 67 [2] ef 52 [2] c1 52 [2] fe 4e }

  condition:
    any of them
}