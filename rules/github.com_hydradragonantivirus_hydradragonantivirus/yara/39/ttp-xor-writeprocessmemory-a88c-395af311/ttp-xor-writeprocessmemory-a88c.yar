rule TTP_XOR_WriteProcessMemory_a88c {
  strings:
    $key_a88c = { ff fe [2] cd dc [2] cb e9 [2] e5 e9 [2] da f5 }

  condition:
    any of them
}