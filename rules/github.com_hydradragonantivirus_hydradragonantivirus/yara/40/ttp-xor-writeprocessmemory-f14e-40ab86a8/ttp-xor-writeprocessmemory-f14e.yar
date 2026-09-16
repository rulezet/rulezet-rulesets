rule TTP_XOR_WriteProcessMemory_f14e {
  strings:
    $key_f14e = { a6 3c [2] 94 1e [2] 92 2b [2] bc 2b [2] 83 37 }

  condition:
    any of them
}