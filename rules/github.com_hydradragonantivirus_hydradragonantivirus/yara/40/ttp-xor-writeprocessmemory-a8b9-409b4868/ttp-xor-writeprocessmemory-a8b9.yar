rule TTP_XOR_WriteProcessMemory_a8b9 {
  strings:
    $key_a8b9 = { ff cb [2] cd e9 [2] cb dc [2] e5 dc [2] da c0 }

  condition:
    any of them
}