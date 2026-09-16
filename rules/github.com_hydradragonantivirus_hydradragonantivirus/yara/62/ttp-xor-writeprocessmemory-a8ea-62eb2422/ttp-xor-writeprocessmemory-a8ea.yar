rule TTP_XOR_WriteProcessMemory_a8ea {
  strings:
    $key_a8ea = { ff 98 [2] cd ba [2] cb 8f [2] e5 8f [2] da 93 }

  condition:
    any of them
}