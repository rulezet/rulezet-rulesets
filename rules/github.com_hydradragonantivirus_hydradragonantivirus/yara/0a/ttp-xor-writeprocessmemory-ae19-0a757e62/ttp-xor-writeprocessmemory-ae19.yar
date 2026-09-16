rule TTP_XOR_WriteProcessMemory_ae19 {
  strings:
    $key_ae19 = { f9 6b [2] cb 49 [2] cd 7c [2] e3 7c [2] dc 60 }

  condition:
    any of them
}