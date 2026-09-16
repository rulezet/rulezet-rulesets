rule TTP_XOR_WriteProcessMemory_f173 {
  strings:
    $key_f173 = { a6 01 [2] 94 23 [2] 92 16 [2] bc 16 [2] 83 0a }

  condition:
    any of them
}