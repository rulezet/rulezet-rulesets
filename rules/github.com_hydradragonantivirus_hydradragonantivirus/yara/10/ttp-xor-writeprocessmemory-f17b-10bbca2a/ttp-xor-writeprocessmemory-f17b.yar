rule TTP_XOR_WriteProcessMemory_f17b {
  strings:
    $key_f17b = { a6 09 [2] 94 2b [2] 92 1e [2] bc 1e [2] 83 02 }

  condition:
    any of them
}