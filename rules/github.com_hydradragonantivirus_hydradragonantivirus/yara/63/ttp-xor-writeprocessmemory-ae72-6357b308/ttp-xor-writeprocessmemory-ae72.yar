rule TTP_XOR_WriteProcessMemory_ae72 {
  strings:
    $key_ae72 = { f9 00 [2] cb 22 [2] cd 17 [2] e3 17 [2] dc 0b }

  condition:
    any of them
}