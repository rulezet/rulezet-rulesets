rule TTP_XOR_WriteProcessMemory_ae8b {
  strings:
    $key_ae8b = { f9 f9 [2] cb db [2] cd ee [2] e3 ee [2] dc f2 }

  condition:
    any of them
}