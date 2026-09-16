rule TTP_XOR_WriteProcessMemory_f1e4 {
  strings:
    $key_f1e4 = { a6 96 [2] 94 b4 [2] 92 81 [2] bc 81 [2] 83 9d }

  condition:
    any of them
}