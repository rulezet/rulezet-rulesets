rule TTP_XOR_WriteProcessMemory_079e {
  strings:
    $key_079e = { 50 ec [2] 62 ce [2] 64 fb [2] 4a fb [2] 75 e7 }

  condition:
    any of them
}