rule TTP_XOR_WriteProcessMemory_a8d6 {
  strings:
    $key_a8d6 = { ff a4 [2] cd 86 [2] cb b3 [2] e5 b3 [2] da af }

  condition:
    any of them
}