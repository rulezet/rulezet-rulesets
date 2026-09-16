rule TTP_XOR_WriteProcessMemory_a851 {
  strings:
    $key_a851 = { ff 23 [2] cd 01 [2] cb 34 [2] e5 34 [2] da 28 }

  condition:
    any of them
}