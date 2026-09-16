rule TTP_XOR_WriteProcessMemory_f1a7 {
  strings:
    $key_f1a7 = { a6 d5 [2] 94 f7 [2] 92 c2 [2] bc c2 [2] 83 de }

  condition:
    any of them
}