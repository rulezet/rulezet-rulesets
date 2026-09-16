rule TTP_XOR_WriteProcessMemory_a855 {
  strings:
    $key_a855 = { ff 27 [2] cd 05 [2] cb 30 [2] e5 30 [2] da 2c }

  condition:
    any of them
}