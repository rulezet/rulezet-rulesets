rule TTP_XOR_WriteProcessMemory_f1d9 {
  strings:
    $key_f1d9 = { a6 ab [2] 94 89 [2] 92 bc [2] bc bc [2] 83 a0 }

  condition:
    any of them
}