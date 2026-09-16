rule TTP_XOR_WriteProcessMemory_2c9e {
  strings:
    $key_2c9e = { 7b ec [2] 49 ce [2] 4f fb [2] 61 fb [2] 5e e7 }

  condition:
    any of them
}