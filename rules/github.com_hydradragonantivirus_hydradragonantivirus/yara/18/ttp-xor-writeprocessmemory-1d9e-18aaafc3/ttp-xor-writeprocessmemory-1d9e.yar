rule TTP_XOR_WriteProcessMemory_1d9e {
  strings:
    $key_1d9e = { 4a ec [2] 78 ce [2] 7e fb [2] 50 fb [2] 6f e7 }

  condition:
    any of them
}