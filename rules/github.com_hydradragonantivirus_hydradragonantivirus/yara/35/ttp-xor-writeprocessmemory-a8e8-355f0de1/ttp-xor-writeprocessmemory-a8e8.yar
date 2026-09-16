rule TTP_XOR_WriteProcessMemory_a8e8 {
  strings:
    $key_a8e8 = { ff 9a [2] cd b8 [2] cb 8d [2] e5 8d [2] da 91 }

  condition:
    any of them
}