rule TTP_XOR_WriteProcessMemory_659e {
  strings:
    $key_659e = { 32 ec [2] 00 ce [2] 06 fb [2] 28 fb [2] 17 e7 }

  condition:
    any of them
}