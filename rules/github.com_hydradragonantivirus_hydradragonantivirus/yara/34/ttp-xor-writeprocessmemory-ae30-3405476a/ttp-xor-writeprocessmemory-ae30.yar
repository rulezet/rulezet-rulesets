rule TTP_XOR_WriteProcessMemory_ae30 {
  strings:
    $key_ae30 = { f9 42 [2] cb 60 [2] cd 55 [2] e3 55 [2] dc 49 }

  condition:
    any of them
}