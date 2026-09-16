rule TTP_XOR_WriteProcessMemory_a8fa {
  strings:
    $key_a8fa = { ff 88 [2] cd aa [2] cb 9f [2] e5 9f [2] da 83 }

  condition:
    any of them
}