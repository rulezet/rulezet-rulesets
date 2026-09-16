rule TTP_XOR_WriteProcessMemory_8c47 {
  strings:
    $key_8c47 = { db 35 [2] e9 17 [2] ef 22 [2] c1 22 [2] fe 3e }

  condition:
    any of them
}