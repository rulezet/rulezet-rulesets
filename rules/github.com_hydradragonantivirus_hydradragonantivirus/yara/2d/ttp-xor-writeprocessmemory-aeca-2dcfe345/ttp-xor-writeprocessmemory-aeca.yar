rule TTP_XOR_WriteProcessMemory_aeca {
  strings:
    $key_aeca = { f9 b8 [2] cb 9a [2] cd af [2] e3 af [2] dc b3 }

  condition:
    any of them
}