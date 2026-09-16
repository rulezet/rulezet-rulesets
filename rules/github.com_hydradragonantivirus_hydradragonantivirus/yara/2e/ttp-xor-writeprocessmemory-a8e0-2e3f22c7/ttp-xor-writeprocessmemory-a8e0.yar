rule TTP_XOR_WriteProcessMemory_a8e0 {
  strings:
    $key_a8e0 = { ff 92 [2] cd b0 [2] cb 85 [2] e5 85 [2] da 99 }

  condition:
    any of them
}