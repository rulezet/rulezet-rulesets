rule TTP_XOR_WriteProcessMemory_a835 {
  strings:
    $key_a835 = { ff 47 [2] cd 65 [2] cb 50 [2] e5 50 [2] da 4c }

  condition:
    any of them
}