rule TTP_XOR_WriteProcessMemory_ae88 {
  strings:
    $key_ae88 = { f9 fa [2] cb d8 [2] cd ed [2] e3 ed [2] dc f1 }

  condition:
    any of them
}