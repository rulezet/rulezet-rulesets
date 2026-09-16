rule TTP_XOR_WriteProcessMemory_ae0f {
  strings:
    $key_ae0f = { f9 7d [2] cb 5f [2] cd 6a [2] e3 6a [2] dc 76 }

  condition:
    any of them
}