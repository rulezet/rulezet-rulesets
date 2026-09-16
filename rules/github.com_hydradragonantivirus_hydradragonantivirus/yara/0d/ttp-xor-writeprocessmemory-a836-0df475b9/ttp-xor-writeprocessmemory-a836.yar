rule TTP_XOR_WriteProcessMemory_a836 {
  strings:
    $key_a836 = { ff 44 [2] cd 66 [2] cb 53 [2] e5 53 [2] da 4f }

  condition:
    any of them
}