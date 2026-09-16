rule TTP_XOR_WriteProcessMemory_f156 {
  strings:
    $key_f156 = { a6 24 [2] 94 06 [2] 92 33 [2] bc 33 [2] 83 2f }

  condition:
    any of them
}