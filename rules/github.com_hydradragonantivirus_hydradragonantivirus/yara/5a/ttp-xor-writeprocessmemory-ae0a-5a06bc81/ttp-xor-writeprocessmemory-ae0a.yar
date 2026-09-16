rule TTP_XOR_WriteProcessMemory_ae0a {
  strings:
    $key_ae0a = { f9 78 [2] cb 5a [2] cd 6f [2] e3 6f [2] dc 73 }

  condition:
    any of them
}