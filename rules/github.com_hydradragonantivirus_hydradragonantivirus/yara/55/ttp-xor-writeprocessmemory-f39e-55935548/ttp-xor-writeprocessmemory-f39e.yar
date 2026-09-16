rule TTP_XOR_WriteProcessMemory_f39e {
  strings:
    $key_f39e = { a4 ec [2] 96 ce [2] 90 fb [2] be fb [2] 81 e7 }

  condition:
    any of them
}