rule TTP_XOR_WriteProcessMemory_ae99 {
  strings:
    $key_ae99 = { f9 eb [2] cb c9 [2] cd fc [2] e3 fc [2] dc e0 }

  condition:
    any of them
}