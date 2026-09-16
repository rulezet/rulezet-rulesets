rule TTP_XOR_WriteProcessMemory_ae80 {
  strings:
    $key_ae80 = { f9 f2 [2] cb d0 [2] cd e5 [2] e3 e5 [2] dc f9 }

  condition:
    any of them
}