rule TTP_XOR_WriteProcessMemory_ae1e {
  strings:
    $key_ae1e = { f9 6c [2] cb 4e [2] cd 7b [2] e3 7b [2] dc 67 }

  condition:
    any of them
}