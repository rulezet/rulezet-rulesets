rule TTP_XOR_WriteProcessMemory_f1f5 {
  strings:
    $key_f1f5 = { a6 87 [2] 94 a5 [2] 92 90 [2] bc 90 [2] 83 8c }

  condition:
    any of them
}