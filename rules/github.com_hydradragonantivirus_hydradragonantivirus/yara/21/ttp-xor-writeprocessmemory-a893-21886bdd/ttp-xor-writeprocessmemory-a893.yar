rule TTP_XOR_WriteProcessMemory_a893 {
  strings:
    $key_a893 = { ff e1 [2] cd c3 [2] cb f6 [2] e5 f6 [2] da ea }

  condition:
    any of them
}