rule TTP_XOR_WriteProcessMemory_4c9e {
  strings:
    $key_4c9e = { 1b ec [2] 29 ce [2] 2f fb [2] 01 fb [2] 3e e7 }

  condition:
    any of them
}