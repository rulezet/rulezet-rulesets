rule TTP_XOR_WriteProcessMemory_ae6c {
  strings:
    $key_ae6c = { f9 1e [2] cb 3c [2] cd 09 [2] e3 09 [2] dc 15 }

  condition:
    any of them
}