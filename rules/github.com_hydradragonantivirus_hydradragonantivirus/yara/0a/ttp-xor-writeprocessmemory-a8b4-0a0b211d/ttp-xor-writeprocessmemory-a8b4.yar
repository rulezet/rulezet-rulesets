rule TTP_XOR_WriteProcessMemory_a8b4 {
  strings:
    $key_a8b4 = { ff c6 [2] cd e4 [2] cb d1 [2] e5 d1 [2] da cd }

  condition:
    any of them
}