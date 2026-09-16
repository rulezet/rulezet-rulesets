rule TTP_XOR_WriteProcessMemory_f29e {
  strings:
    $key_f29e = { a5 ec [2] 97 ce [2] 91 fb [2] bf fb [2] 80 e7 }

  condition:
    any of them
}