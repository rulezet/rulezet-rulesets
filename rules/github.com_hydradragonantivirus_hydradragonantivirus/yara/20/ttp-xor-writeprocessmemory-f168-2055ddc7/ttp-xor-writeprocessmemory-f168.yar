rule TTP_XOR_WriteProcessMemory_f168 {
  strings:
    $key_f168 = { a6 1a [2] 94 38 [2] 92 0d [2] bc 0d [2] 83 11 }

  condition:
    any of them
}