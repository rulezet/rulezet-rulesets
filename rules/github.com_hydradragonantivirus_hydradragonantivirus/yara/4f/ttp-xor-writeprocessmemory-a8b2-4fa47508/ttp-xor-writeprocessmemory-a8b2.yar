rule TTP_XOR_WriteProcessMemory_a8b2 {
  strings:
    $key_a8b2 = { ff c0 [2] cd e2 [2] cb d7 [2] e5 d7 [2] da cb }

  condition:
    any of them
}