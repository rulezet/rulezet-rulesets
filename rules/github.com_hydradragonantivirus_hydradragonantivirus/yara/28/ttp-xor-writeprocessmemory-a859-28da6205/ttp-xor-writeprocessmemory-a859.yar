rule TTP_XOR_WriteProcessMemory_a859 {
  strings:
    $key_a859 = { ff 2b [2] cd 09 [2] cb 3c [2] e5 3c [2] da 20 }

  condition:
    any of them
}