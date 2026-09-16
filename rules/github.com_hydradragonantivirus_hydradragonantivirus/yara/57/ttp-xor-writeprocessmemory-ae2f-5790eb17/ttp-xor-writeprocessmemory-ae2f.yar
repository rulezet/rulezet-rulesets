rule TTP_XOR_WriteProcessMemory_ae2f {
  strings:
    $key_ae2f = { f9 5d [2] cb 7f [2] cd 4a [2] e3 4a [2] dc 56 }

  condition:
    any of them
}