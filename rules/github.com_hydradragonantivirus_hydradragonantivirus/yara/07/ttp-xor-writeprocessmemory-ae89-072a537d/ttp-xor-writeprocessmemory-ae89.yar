rule TTP_XOR_WriteProcessMemory_ae89 {
  strings:
    $key_ae89 = { f9 fb [2] cb d9 [2] cd ec [2] e3 ec [2] dc f0 }

  condition:
    any of them
}