rule TTP_XOR_WriteProcessMemory_a8d7 {
  strings:
    $key_a8d7 = { ff a5 [2] cd 87 [2] cb b2 [2] e5 b2 [2] da ae }

  condition:
    any of them
}