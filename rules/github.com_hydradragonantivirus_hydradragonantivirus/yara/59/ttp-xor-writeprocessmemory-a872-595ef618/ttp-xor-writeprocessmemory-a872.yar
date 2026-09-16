rule TTP_XOR_WriteProcessMemory_a872 {
  strings:
    $key_a872 = { ff 00 [2] cd 22 [2] cb 17 [2] e5 17 [2] da 0b }

  condition:
    any of them
}