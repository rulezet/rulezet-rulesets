rule TTP_XOR_WriteProcessMemory_a818 {
  strings:
    $key_a818 = { ff 6a [2] cd 48 [2] cb 7d [2] e5 7d [2] da 61 }

  condition:
    any of them
}