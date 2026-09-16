rule TTP_XOR_WriteProcessMemory_a823 {
  strings:
    $key_a823 = { ff 51 [2] cd 73 [2] cb 46 [2] e5 46 [2] da 5a }

  condition:
    any of them
}