rule TTP_XOR_WriteProcessMemory_ae11 {
  strings:
    $key_ae11 = { f9 63 [2] cb 41 [2] cd 74 [2] e3 74 [2] dc 68 }

  condition:
    any of them
}