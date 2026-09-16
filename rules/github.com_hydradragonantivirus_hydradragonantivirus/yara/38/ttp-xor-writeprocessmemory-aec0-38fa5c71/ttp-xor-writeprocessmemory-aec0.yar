rule TTP_XOR_WriteProcessMemory_aec0 {
  strings:
    $key_aec0 = { f9 b2 [2] cb 90 [2] cd a5 [2] e3 a5 [2] dc b9 }

  condition:
    any of them
}