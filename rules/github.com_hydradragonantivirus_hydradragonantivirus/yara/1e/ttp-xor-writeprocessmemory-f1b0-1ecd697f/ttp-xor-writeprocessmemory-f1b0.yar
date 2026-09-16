rule TTP_XOR_WriteProcessMemory_f1b0 {
  strings:
    $key_f1b0 = { a6 c2 [2] 94 e0 [2] 92 d5 [2] bc d5 [2] 83 c9 }

  condition:
    any of them
}