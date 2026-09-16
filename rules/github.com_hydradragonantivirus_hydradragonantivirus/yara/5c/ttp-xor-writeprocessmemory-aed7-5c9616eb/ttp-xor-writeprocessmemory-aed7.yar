rule TTP_XOR_WriteProcessMemory_aed7 {
  strings:
    $key_aed7 = { f9 a5 [2] cb 87 [2] cd b2 [2] e3 b2 [2] dc ae }

  condition:
    any of them
}