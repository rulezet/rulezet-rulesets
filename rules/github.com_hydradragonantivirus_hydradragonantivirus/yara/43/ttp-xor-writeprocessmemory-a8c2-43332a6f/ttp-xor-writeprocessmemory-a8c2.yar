rule TTP_XOR_WriteProcessMemory_a8c2 {
  strings:
    $key_a8c2 = { ff b0 [2] cd 92 [2] cb a7 [2] e5 a7 [2] da bb }

  condition:
    any of them
}