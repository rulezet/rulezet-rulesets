rule TTP_XOR_WriteProcessMemory_ae63 {
  strings:
    $key_ae63 = { f9 11 [2] cb 33 [2] cd 06 [2] e3 06 [2] dc 1a }

  condition:
    any of them
}