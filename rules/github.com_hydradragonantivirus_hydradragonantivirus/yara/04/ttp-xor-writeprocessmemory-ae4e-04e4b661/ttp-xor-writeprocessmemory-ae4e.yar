rule TTP_XOR_WriteProcessMemory_ae4e {
  strings:
    $key_ae4e = { f9 3c [2] cb 1e [2] cd 2b [2] e3 2b [2] dc 37 }

  condition:
    any of them
}