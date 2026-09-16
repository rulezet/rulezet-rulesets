rule TTP_XOR_WriteProcessMemory_a863 {
  strings:
    $key_a863 = { ff 11 [2] cd 33 [2] cb 06 [2] e5 06 [2] da 1a }

  condition:
    any of them
}