rule TTP_XOR_WriteProcessMemory_ae6a {
  strings:
    $key_ae6a = { f9 18 [2] cb 3a [2] cd 0f [2] e3 0f [2] dc 13 }

  condition:
    any of them
}