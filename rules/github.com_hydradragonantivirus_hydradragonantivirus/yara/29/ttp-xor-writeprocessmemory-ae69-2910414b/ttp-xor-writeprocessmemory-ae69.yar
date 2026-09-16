rule TTP_XOR_WriteProcessMemory_ae69 {
  strings:
    $key_ae69 = { f9 1b [2] cb 39 [2] cd 0c [2] e3 0c [2] dc 10 }

  condition:
    any of them
}