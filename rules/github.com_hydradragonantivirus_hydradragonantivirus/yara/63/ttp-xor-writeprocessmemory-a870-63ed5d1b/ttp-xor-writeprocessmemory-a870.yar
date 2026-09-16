rule TTP_XOR_WriteProcessMemory_a870 {
  strings:
    $key_a870 = { ff 02 [2] cd 20 [2] cb 15 [2] e5 15 [2] da 09 }

  condition:
    any of them
}