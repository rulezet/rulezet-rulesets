rule TTP_XOR_WriteProcessMemory_a8fe {
  strings:
    $key_a8fe = { ff 8c [2] cd ae [2] cb 9b [2] e5 9b [2] da 87 }

  condition:
    any of them
}