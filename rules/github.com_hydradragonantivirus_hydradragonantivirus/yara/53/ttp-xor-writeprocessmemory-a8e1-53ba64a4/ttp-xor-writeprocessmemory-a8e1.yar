rule TTP_XOR_WriteProcessMemory_a8e1 {
  strings:
    $key_a8e1 = { ff 93 [2] cd b1 [2] cb 84 [2] e5 84 [2] da 98 }

  condition:
    any of them
}