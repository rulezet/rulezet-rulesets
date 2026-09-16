rule TTP_XOR_WriteProcessMemory_a860 {
  strings:
    $key_a860 = { ff 12 [2] cd 30 [2] cb 05 [2] e5 05 [2] da 19 }

  condition:
    any of them
}