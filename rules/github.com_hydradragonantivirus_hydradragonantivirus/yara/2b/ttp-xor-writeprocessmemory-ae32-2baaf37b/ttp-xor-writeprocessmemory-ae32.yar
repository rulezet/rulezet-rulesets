rule TTP_XOR_WriteProcessMemory_ae32 {
  strings:
    $key_ae32 = { f9 40 [2] cb 62 [2] cd 57 [2] e3 57 [2] dc 4b }

  condition:
    any of them
}