rule TTP_XOR_WriteProcessMemory_aeb9 {
  strings:
    $key_aeb9 = { f9 cb [2] cb e9 [2] cd dc [2] e3 dc [2] dc c0 }

  condition:
    any of them
}