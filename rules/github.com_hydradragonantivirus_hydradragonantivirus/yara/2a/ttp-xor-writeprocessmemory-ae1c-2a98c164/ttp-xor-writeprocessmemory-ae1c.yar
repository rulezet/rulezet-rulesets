rule TTP_XOR_WriteProcessMemory_ae1c {
  strings:
    $key_ae1c = { f9 6e [2] cb 4c [2] cd 79 [2] e3 79 [2] dc 65 }

  condition:
    any of them
}