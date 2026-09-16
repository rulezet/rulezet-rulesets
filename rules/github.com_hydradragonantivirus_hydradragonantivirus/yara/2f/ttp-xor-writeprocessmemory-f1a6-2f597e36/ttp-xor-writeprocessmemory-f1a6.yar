rule TTP_XOR_WriteProcessMemory_f1a6 {
  strings:
    $key_f1a6 = { a6 d4 [2] 94 f6 [2] 92 c3 [2] bc c3 [2] 83 df }

  condition:
    any of them
}