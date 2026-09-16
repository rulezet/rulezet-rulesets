rule TTP_XOR_WriteProcessMemory_a8a3 {
  strings:
    $key_a8a3 = { ff d1 [2] cd f3 [2] cb c6 [2] e5 c6 [2] da da }

  condition:
    any of them
}