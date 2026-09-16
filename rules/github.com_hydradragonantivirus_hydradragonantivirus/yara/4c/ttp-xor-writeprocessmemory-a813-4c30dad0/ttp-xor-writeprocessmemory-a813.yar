rule TTP_XOR_WriteProcessMemory_a813 {
  strings:
    $key_a813 = { ff 61 [2] cd 43 [2] cb 76 [2] e5 76 [2] da 6a }

  condition:
    any of them
}