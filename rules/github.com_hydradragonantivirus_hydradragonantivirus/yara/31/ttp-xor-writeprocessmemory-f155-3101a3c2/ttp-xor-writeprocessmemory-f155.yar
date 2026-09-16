rule TTP_XOR_WriteProcessMemory_f155 {
  strings:
    $key_f155 = { a6 27 [2] 94 05 [2] 92 30 [2] bc 30 [2] 83 2c }

  condition:
    any of them
}