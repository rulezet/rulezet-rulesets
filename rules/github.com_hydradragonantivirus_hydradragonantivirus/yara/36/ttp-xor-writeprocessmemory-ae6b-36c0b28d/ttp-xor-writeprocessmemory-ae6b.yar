rule TTP_XOR_WriteProcessMemory_ae6b {
  strings:
    $key_ae6b = { f9 19 [2] cb 3b [2] cd 0e [2] e3 0e [2] dc 12 }

  condition:
    any of them
}