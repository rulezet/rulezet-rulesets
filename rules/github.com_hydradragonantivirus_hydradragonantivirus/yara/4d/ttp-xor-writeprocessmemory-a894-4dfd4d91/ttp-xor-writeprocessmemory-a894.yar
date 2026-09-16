rule TTP_XOR_WriteProcessMemory_a894 {
  strings:
    $key_a894 = { ff e6 [2] cd c4 [2] cb f1 [2] e5 f1 [2] da ed }

  condition:
    any of them
}