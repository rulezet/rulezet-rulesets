rule TTP_XOR_WriteProcessMemory_f19e {
  strings:
    $key_f19e = { a6 ec [2] 94 ce [2] 92 fb [2] bc fb [2] 83 e7 }

  condition:
    any of them
}