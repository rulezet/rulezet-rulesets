rule TTP_XOR_WriteProcessMemory_a801 {
  strings:
    $key_a801 = { ff 73 [2] cd 51 [2] cb 64 [2] e5 64 [2] da 78 }

  condition:
    any of them
}