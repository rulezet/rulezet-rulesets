rule TTP_XOR_WriteProcessMemory_ae9e {
  strings:
    $key_ae9e = { f9 ec [2] cb ce [2] cd fb [2] e3 fb [2] dc e7 }

  condition:
    any of them
}