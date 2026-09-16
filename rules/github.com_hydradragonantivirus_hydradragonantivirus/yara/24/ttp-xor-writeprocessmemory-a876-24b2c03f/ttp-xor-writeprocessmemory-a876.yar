rule TTP_XOR_WriteProcessMemory_a876 {
  strings:
    $key_a876 = { ff 04 [2] cd 26 [2] cb 13 [2] e5 13 [2] da 0f }

  condition:
    any of them
}