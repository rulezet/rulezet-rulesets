rule TTP_XOR_WriteProcessMemory_f1d2 {
  strings:
    $key_f1d2 = { a6 a0 [2] 94 82 [2] 92 b7 [2] bc b7 [2] 83 ab }

  condition:
    any of them
}