rule TTP_XOR_WriteProcessMemory_a83a {
  strings:
    $key_a83a = { ff 48 [2] cd 6a [2] cb 5f [2] e5 5f [2] da 43 }

  condition:
    any of them
}