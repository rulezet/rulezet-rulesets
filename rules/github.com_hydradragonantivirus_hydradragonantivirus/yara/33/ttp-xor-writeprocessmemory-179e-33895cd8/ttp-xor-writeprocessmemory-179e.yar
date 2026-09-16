rule TTP_XOR_WriteProcessMemory_179e {
  strings:
    $key_179e = { 40 ec [2] 72 ce [2] 74 fb [2] 5a fb [2] 65 e7 }

  condition:
    any of them
}