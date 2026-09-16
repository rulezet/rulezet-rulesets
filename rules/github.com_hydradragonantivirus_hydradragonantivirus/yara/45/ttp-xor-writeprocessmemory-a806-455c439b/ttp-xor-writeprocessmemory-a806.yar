rule TTP_XOR_WriteProcessMemory_a806 {
  strings:
    $key_a806 = { ff 74 [2] cd 56 [2] cb 63 [2] e5 63 [2] da 7f }

  condition:
    any of them
}