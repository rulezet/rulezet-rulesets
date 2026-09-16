rule TTP_XOR_WriteProcessMemory_ae49 {
  strings:
    $key_ae49 = { f9 3b [2] cb 19 [2] cd 2c [2] e3 2c [2] dc 30 }

  condition:
    any of them
}