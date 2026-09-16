rule TTP_XOR_WriteProcessMemory_ae00 {
  strings:
    $key_ae00 = { f9 72 [2] cb 50 [2] cd 65 [2] e3 65 [2] dc 79 }

  condition:
    any of them
}