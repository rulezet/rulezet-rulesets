rule TTP_XOR_WriteProcessMemory_a891 {
  strings:
    $key_a891 = { ff e3 [2] cd c1 [2] cb f4 [2] e5 f4 [2] da e8 }

  condition:
    any of them
}