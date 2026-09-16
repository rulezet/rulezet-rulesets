rule TTP_XOR_WriteProcessMemory_0b9e {
  strings:
    $key_0b9e = { 5c ec [2] 6e ce [2] 68 fb [2] 46 fb [2] 79 e7 }

  condition:
    any of them
}