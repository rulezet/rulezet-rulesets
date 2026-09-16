rule TTP_XOR_WriteProcessMemory_f1f3 {
  strings:
    $key_f1f3 = { a6 81 [2] 94 a3 [2] 92 96 [2] bc 96 [2] 83 8a }

  condition:
    any of them
}