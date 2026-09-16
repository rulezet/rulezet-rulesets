rule TTP_XOR_WriteProcessMemory_f1e0 {
  strings:
    $key_f1e0 = { a6 92 [2] 94 b0 [2] 92 85 [2] bc 85 [2] 83 99 }

  condition:
    any of them
}