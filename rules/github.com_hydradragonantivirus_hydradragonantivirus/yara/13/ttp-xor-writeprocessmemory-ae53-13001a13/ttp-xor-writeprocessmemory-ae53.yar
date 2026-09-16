rule TTP_XOR_WriteProcessMemory_ae53 {
  strings:
    $key_ae53 = { f9 21 [2] cb 03 [2] cd 36 [2] e3 36 [2] dc 2a }

  condition:
    any of them
}