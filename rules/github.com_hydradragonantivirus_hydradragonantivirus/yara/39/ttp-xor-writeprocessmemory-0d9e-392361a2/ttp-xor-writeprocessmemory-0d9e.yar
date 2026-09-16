rule TTP_XOR_WriteProcessMemory_0d9e {
  strings:
    $key_0d9e = { 5a ec [2] 68 ce [2] 6e fb [2] 40 fb [2] 7f e7 }

  condition:
    any of them
}