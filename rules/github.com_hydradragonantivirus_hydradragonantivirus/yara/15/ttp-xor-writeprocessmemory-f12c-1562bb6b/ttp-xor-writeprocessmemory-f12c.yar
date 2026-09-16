rule TTP_XOR_WriteProcessMemory_f12c {
  strings:
    $key_f12c = { a6 5e [2] 94 7c [2] 92 49 [2] bc 49 [2] 83 55 }

  condition:
    any of them
}