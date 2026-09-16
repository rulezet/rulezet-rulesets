rule TTP_XOR_WriteProcessMemory_f1bc {
  strings:
    $key_f1bc = { a6 ce [2] 94 ec [2] 92 d9 [2] bc d9 [2] 83 c5 }

  condition:
    any of them
}