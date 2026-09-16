rule TTP_XOR_WriteProcessMemory_a814 {
  strings:
    $key_a814 = { ff 66 [2] cd 44 [2] cb 71 [2] e5 71 [2] da 6d }

  condition:
    any of them
}