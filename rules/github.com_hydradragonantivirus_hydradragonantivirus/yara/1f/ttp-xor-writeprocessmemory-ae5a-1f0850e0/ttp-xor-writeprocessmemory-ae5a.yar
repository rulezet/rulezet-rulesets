rule TTP_XOR_WriteProcessMemory_ae5a {
  strings:
    $key_ae5a = { f9 28 [2] cb 0a [2] cd 3f [2] e3 3f [2] dc 23 }

  condition:
    any of them
}