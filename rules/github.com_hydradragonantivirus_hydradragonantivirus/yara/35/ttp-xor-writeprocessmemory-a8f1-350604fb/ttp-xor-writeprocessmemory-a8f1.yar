rule TTP_XOR_WriteProcessMemory_a8f1 {
  strings:
    $key_a8f1 = { ff 83 [2] cd a1 [2] cb 94 [2] e5 94 [2] da 88 }

  condition:
    any of them
}