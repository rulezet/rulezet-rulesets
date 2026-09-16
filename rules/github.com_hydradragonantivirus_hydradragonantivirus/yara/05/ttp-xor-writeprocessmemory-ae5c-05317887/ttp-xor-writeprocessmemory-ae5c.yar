rule TTP_XOR_WriteProcessMemory_ae5c {
  strings:
    $key_ae5c = { f9 2e [2] cb 0c [2] cd 39 [2] e3 39 [2] dc 25 }

  condition:
    any of them
}