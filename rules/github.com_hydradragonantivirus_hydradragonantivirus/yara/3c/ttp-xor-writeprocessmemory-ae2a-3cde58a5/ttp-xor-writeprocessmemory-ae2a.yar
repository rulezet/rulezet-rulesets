rule TTP_XOR_WriteProcessMemory_ae2a {
  strings:
    $key_ae2a = { f9 58 [2] cb 7a [2] cd 4f [2] e3 4f [2] dc 53 }

  condition:
    any of them
}