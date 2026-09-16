rule TTP_XOR_WriteProcessMemory_a826 {
  strings:
    $key_a826 = { ff 54 [2] cd 76 [2] cb 43 [2] e5 43 [2] da 5f }

  condition:
    any of them
}