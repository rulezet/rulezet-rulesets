rule TTP_XOR_WriteProcessMemory_ae8a {
  strings:
    $key_ae8a = { f9 f8 [2] cb da [2] cd ef [2] e3 ef [2] dc f3 }

  condition:
    any of them
}