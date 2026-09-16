rule TTP_XOR_WriteProcessMemory_ae56 {
  strings:
    $key_ae56 = { f9 24 [2] cb 06 [2] cd 33 [2] e3 33 [2] dc 2f }

  condition:
    any of them
}