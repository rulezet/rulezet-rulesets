rule TTP_XOR_WriteProcessMemory_f1a5 {
  strings:
    $key_f1a5 = { a6 d7 [2] 94 f5 [2] 92 c0 [2] bc c0 [2] 83 dc }

  condition:
    any of them
}