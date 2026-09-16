rule TTP_XOR_WriteProcessMemory_5d9e {
  strings:
    $key_5d9e = { 0a ec [2] 38 ce [2] 3e fb [2] 10 fb [2] 2f e7 }

  condition:
    any of them
}