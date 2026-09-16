rule TTP_XOR_WriteProcessMemory_a8e6 {
  strings:
    $key_a8e6 = { ff 94 [2] cd b6 [2] cb 83 [2] e5 83 [2] da 9f }

  condition:
    any of them
}