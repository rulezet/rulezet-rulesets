rule TTP_XOR_WriteProcessMemory_f152 {
  strings:
    $key_f152 = { a6 20 [2] 94 02 [2] 92 37 [2] bc 37 [2] 83 2b }

  condition:
    any of them
}