rule TTP_XOR_WriteProcessMemory_a8a0 {
  strings:
    $key_a8a0 = { ff d2 [2] cd f0 [2] cb c5 [2] e5 c5 [2] da d9 }

  condition:
    any of them
}