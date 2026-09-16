rule TTP_XOR_WriteProcessMemory_a8b0 {
  strings:
    $key_a8b0 = { ff c2 [2] cd e0 [2] cb d5 [2] e5 d5 [2] da c9 }

  condition:
    any of them
}