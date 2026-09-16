rule TTP_XOR_WriteProcessMemory_e69e {
  strings:
    $key_e69e = { b1 ec [2] 83 ce [2] 85 fb [2] ab fb [2] 94 e7 }

  condition:
    any of them
}