rule TTP_XOR_WriteProcessMemory_a841 {
  strings:
    $key_a841 = { ff 33 [2] cd 11 [2] cb 24 [2] e5 24 [2] da 38 }

  condition:
    any of them
}