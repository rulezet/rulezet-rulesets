rule TTP_XOR_WriteProcessMemory_6b9e {
  strings:
    $key_6b9e = { 3c ec [2] 0e ce [2] 08 fb [2] 26 fb [2] 19 e7 }

  condition:
    any of them
}