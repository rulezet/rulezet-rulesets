rule TTP_XOR_WriteProcessMemory_a834 {
  strings:
    $key_a834 = { ff 46 [2] cd 64 [2] cb 51 [2] e5 51 [2] da 4d }

  condition:
    any of them
}