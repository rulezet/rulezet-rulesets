rule TTP_XOR_WriteProcessMemory_ae81 {
  strings:
    $key_ae81 = { f9 f3 [2] cb d1 [2] cd e4 [2] e3 e4 [2] dc f8 }

  condition:
    any of them
}