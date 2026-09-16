rule TTP_XOR_WriteProcessMemory_f146 {
  strings:
    $key_f146 = { a6 34 [2] 94 16 [2] 92 23 [2] bc 23 [2] 83 3f }

  condition:
    any of them
}