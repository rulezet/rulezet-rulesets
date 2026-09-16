rule TTP_XOR_WriteProcessMemory_a899 {
  strings:
    $key_a899 = { ff eb [2] cd c9 [2] cb fc [2] e5 fc [2] da e0 }

  condition:
    any of them
}