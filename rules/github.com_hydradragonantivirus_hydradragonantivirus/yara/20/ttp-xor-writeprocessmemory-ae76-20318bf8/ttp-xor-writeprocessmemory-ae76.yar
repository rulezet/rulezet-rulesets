rule TTP_XOR_WriteProcessMemory_ae76 {
  strings:
    $key_ae76 = { f9 04 [2] cb 26 [2] cd 13 [2] e3 13 [2] dc 0f }

  condition:
    any of them
}