rule TTP_XOR_WriteProcessMemory_a8b3 {
  strings:
    $key_a8b3 = { ff c1 [2] cd e3 [2] cb d6 [2] e5 d6 [2] da ca }

  condition:
    any of them
}