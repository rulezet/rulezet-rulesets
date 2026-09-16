rule TTP_XOR_WriteProcessMemory_749e {
  strings:
    $key_749e = { 23 ec [2] 11 ce [2] 17 fb [2] 39 fb [2] 06 e7 }

  condition:
    any of them
}