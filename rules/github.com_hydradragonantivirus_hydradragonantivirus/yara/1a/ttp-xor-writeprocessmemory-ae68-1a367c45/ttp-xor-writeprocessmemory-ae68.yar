rule TTP_XOR_WriteProcessMemory_ae68 {
  strings:
    $key_ae68 = { f9 1a [2] cb 38 [2] cd 0d [2] e3 0d [2] dc 11 }

  condition:
    any of them
}