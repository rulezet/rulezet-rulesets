rule TTP_XOR_WriteProcessMemory_f14c {
  strings:
    $key_f14c = { a6 3e [2] 94 1c [2] 92 29 [2] bc 29 [2] 83 35 }

  condition:
    any of them
}