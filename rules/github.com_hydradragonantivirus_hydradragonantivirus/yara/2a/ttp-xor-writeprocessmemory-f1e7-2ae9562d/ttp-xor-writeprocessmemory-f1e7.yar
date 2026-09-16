rule TTP_XOR_WriteProcessMemory_f1e7 {
  strings:
    $key_f1e7 = { a6 95 [2] 94 b7 [2] 92 82 [2] bc 82 [2] 83 9e }

  condition:
    any of them
}