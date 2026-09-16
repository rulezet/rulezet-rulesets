rule TTP_XOR_WriteProcessMemory_aeb0 {
  strings:
    $key_aeb0 = { f9 c2 [2] cb e0 [2] cd d5 [2] e3 d5 [2] dc c9 }

  condition:
    any of them
}