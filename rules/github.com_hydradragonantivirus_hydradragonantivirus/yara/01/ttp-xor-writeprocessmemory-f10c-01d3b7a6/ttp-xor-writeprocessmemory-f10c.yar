rule TTP_XOR_WriteProcessMemory_f10c {
  strings:
    $key_f10c = { a6 7e [2] 94 5c [2] 92 69 [2] bc 69 [2] 83 75 }

  condition:
    any of them
}