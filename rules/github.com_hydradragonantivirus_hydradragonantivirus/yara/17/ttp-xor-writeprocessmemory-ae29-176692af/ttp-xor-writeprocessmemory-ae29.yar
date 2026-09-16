rule TTP_XOR_WriteProcessMemory_ae29 {
  strings:
    $key_ae29 = { f9 5b [2] cb 79 [2] cd 4c [2] e3 4c [2] dc 50 }

  condition:
    any of them
}