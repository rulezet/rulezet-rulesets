rule TTP_XOR_WriteProcessMemory_a8f8 {
  strings:
    $key_a8f8 = { ff 8a [2] cd a8 [2] cb 9d [2] e5 9d [2] da 81 }

  condition:
    any of them
}