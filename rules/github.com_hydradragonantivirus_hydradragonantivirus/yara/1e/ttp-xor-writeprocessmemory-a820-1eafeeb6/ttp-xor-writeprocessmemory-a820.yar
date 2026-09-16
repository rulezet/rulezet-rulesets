rule TTP_XOR_WriteProcessMemory_a820 {
  strings:
    $key_a820 = { ff 52 [2] cd 70 [2] cb 45 [2] e5 45 [2] da 59 }

  condition:
    any of them
}