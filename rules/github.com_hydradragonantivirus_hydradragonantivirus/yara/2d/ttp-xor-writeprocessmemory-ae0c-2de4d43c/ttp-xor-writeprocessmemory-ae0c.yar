rule TTP_XOR_WriteProcessMemory_ae0c {
  strings:
    $key_ae0c = { f9 7e [2] cb 5c [2] cd 69 [2] e3 69 [2] dc 75 }

  condition:
    any of them
}