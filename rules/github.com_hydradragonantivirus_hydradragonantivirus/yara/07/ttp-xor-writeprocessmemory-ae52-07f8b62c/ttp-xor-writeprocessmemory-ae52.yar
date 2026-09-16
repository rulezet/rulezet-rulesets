rule TTP_XOR_WriteProcessMemory_ae52 {
  strings:
    $key_ae52 = { f9 20 [2] cb 02 [2] cd 37 [2] e3 37 [2] dc 2b }

  condition:
    any of them
}