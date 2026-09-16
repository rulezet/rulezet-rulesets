rule TTP_XOR_WriteProcessMemory_f1f0 {
  strings:
    $key_f1f0 = { a6 82 [2] 94 a0 [2] 92 95 [2] bc 95 [2] 83 89 }

  condition:
    any of them
}