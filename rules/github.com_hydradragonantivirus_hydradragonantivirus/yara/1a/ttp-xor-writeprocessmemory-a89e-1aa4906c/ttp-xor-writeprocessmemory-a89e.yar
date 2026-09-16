rule TTP_XOR_WriteProcessMemory_a89e {
  strings:
    $key_a89e = { ff ec [2] cd ce [2] cb fb [2] e5 fb [2] da e7 }

  condition:
    any of them
}