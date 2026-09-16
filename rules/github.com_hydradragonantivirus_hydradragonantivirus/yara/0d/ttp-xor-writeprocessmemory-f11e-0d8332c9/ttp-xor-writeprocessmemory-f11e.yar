rule TTP_XOR_WriteProcessMemory_f11e {
  strings:
    $key_f11e = { a6 6c [2] 94 4e [2] 92 7b [2] bc 7b [2] 83 67 }

  condition:
    any of them
}