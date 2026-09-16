rule TTP_XOR_WriteProcessMemory_a8ff {
  strings:
    $key_a8ff = { ff 8d [2] cd af [2] cb 9a [2] e5 9a [2] da 86 }

  condition:
    any of them
}