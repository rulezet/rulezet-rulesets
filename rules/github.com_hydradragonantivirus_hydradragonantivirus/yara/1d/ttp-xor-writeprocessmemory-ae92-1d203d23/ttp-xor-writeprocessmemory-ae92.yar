rule TTP_XOR_WriteProcessMemory_ae92 {
  strings:
    $key_ae92 = { f9 e0 [2] cb c2 [2] cd f7 [2] e3 f7 [2] dc eb }

  condition:
    any of them
}