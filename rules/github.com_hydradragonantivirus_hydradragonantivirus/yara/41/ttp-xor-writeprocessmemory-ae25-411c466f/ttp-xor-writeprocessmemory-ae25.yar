rule TTP_XOR_WriteProcessMemory_ae25 {
  strings:
    $key_ae25 = { f9 57 [2] cb 75 [2] cd 40 [2] e3 40 [2] dc 5c }

  condition:
    any of them
}