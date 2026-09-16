rule TTP_XOR_WriteProcessMemory_a881 {
  strings:
    $key_a881 = { ff f3 [2] cd d1 [2] cb e4 [2] e5 e4 [2] da f8 }

  condition:
    any of them
}