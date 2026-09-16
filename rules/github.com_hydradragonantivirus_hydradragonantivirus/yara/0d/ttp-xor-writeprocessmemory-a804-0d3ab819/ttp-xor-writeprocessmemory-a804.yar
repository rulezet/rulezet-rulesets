rule TTP_XOR_WriteProcessMemory_a804 {
  strings:
    $key_a804 = { ff 76 [2] cd 54 [2] cb 61 [2] e5 61 [2] da 7d }

  condition:
    any of them
}