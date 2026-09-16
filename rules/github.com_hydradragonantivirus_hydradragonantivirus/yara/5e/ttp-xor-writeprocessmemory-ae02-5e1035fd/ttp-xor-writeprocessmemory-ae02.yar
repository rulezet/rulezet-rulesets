rule TTP_XOR_WriteProcessMemory_ae02 {
  strings:
    $key_ae02 = { f9 70 [2] cb 52 [2] cd 67 [2] e3 67 [2] dc 7b }

  condition:
    any of them
}