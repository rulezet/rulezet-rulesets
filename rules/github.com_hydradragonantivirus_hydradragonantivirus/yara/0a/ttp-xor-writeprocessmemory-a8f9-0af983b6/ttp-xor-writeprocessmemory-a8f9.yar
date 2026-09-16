rule TTP_XOR_WriteProcessMemory_a8f9 {
  strings:
    $key_a8f9 = { ff 8b [2] cd a9 [2] cb 9c [2] e5 9c [2] da 80 }

  condition:
    any of them
}