rule TTP_XOR_WriteProcessMemory_f1b1 {
  strings:
    $key_f1b1 = { a6 c3 [2] 94 e1 [2] 92 d4 [2] bc d4 [2] 83 c8 }

  condition:
    any of them
}