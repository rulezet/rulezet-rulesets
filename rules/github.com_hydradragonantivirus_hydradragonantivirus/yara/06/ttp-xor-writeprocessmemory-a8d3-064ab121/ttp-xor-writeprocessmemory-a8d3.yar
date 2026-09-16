rule TTP_XOR_WriteProcessMemory_a8d3 {
  strings:
    $key_a8d3 = { ff a1 [2] cd 83 [2] cb b6 [2] e5 b6 [2] da aa }

  condition:
    any of them
}