rule TTP_XOR_WriteProcessMemory_a8ab {
  strings:
    $key_a8ab = { ff d9 [2] cd fb [2] cb ce [2] e5 ce [2] da d2 }

  condition:
    any of them
}