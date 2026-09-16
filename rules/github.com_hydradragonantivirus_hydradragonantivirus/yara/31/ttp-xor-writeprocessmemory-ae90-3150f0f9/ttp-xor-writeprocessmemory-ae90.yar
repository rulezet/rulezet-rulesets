rule TTP_XOR_WriteProcessMemory_ae90 {
  strings:
    $key_ae90 = { f9 e2 [2] cb c0 [2] cd f5 [2] e3 f5 [2] dc e9 }

  condition:
    any of them
}