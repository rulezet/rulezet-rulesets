rule TTP_XOR_WriteProcessMemory_a8c1 {
  strings:
    $key_a8c1 = { ff b3 [2] cd 91 [2] cb a4 [2] e5 a4 [2] da b8 }

  condition:
    any of them
}