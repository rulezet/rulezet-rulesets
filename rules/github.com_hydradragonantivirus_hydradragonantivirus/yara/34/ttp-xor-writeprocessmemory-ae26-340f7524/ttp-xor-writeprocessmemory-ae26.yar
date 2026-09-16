rule TTP_XOR_WriteProcessMemory_ae26 {
  strings:
    $key_ae26 = { f9 54 [2] cb 76 [2] cd 43 [2] e3 43 [2] dc 5f }

  condition:
    any of them
}