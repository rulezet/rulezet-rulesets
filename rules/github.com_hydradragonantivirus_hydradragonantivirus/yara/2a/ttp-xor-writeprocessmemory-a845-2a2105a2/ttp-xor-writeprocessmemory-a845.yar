rule TTP_XOR_WriteProcessMemory_a845 {
  strings:
    $key_a845 = { ff 37 [2] cd 15 [2] cb 20 [2] e5 20 [2] da 3c }

  condition:
    any of them
}