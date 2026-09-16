rule TTP_XOR_WriteProcessMemory_ae07 {
  strings:
    $key_ae07 = { f9 75 [2] cb 57 [2] cd 62 [2] e3 62 [2] dc 7e }

  condition:
    any of them
}