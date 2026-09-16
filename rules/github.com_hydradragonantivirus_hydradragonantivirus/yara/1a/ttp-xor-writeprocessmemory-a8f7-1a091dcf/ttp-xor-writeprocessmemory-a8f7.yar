rule TTP_XOR_WriteProcessMemory_a8f7 {
  strings:
    $key_a8f7 = { ff 85 [2] cd a7 [2] cb 92 [2] e5 92 [2] da 8e }

  condition:
    any of them
}