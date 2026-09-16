rule TTP_XOR_WriteProcessMemory_a86a {
  strings:
    $key_a86a = { ff 18 [2] cd 3a [2] cb 0f [2] e5 0f [2] da 13 }

  condition:
    any of them
}