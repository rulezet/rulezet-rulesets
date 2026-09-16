rule TTP_XOR_WriteProcessMemory_a8c3 {
  strings:
    $key_a8c3 = { ff b1 [2] cd 93 [2] cb a6 [2] e5 a6 [2] da ba }

  condition:
    any of them
}