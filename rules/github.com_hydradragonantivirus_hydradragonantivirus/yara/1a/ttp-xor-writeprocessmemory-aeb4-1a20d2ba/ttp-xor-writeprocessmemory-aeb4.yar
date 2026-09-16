rule TTP_XOR_WriteProcessMemory_aeb4 {
  strings:
    $key_aeb4 = { f9 c6 [2] cb e4 [2] cd d1 [2] e3 d1 [2] dc cd }

  condition:
    any of them
}