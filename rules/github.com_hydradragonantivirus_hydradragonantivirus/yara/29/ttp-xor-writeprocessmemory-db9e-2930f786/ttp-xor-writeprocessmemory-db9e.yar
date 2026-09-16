rule TTP_XOR_WriteProcessMemory_db9e {
  strings:
    $key_db9e = { 8c ec [2] be ce [2] b8 fb [2] 96 fb [2] a9 e7 }

  condition:
    any of them
}