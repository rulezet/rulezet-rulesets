rule TTP_XOR_WriteProcessMemory_ae55 {
  strings:
    $key_ae55 = { f9 27 [2] cb 05 [2] cd 30 [2] e3 30 [2] dc 2c }

  condition:
    any of them
}