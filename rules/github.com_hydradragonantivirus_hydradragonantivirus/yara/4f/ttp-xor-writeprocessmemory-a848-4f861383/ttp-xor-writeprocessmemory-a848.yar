rule TTP_XOR_WriteProcessMemory_a848 {
  strings:
    $key_a848 = { ff 3a [2] cd 18 [2] cb 2d [2] e5 2d [2] da 31 }

  condition:
    any of them
}