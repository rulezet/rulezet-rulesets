rule TTP_XOR_WriteProcessMemory_ae14 {
  strings:
    $key_ae14 = { f9 66 [2] cb 44 [2] cd 71 [2] e3 71 [2] dc 6d }

  condition:
    any of them
}