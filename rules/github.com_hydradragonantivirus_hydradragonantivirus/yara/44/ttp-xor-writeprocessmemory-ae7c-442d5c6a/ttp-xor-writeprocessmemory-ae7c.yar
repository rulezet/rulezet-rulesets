rule TTP_XOR_WriteProcessMemory_ae7c {
  strings:
    $key_ae7c = { f9 0e [2] cb 2c [2] cd 19 [2] e3 19 [2] dc 05 }

  condition:
    any of them
}