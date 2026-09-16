rule TTP_XOR_WriteProcessMemory_ae1d {
  strings:
    $key_ae1d = { f9 6f [2] cb 4d [2] cd 78 [2] e3 78 [2] dc 64 }

  condition:
    any of them
}