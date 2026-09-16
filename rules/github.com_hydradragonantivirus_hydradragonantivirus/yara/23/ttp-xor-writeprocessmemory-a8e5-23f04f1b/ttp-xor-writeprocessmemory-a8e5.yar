rule TTP_XOR_WriteProcessMemory_a8e5 {
  strings:
    $key_a8e5 = { ff 97 [2] cd b5 [2] cb 80 [2] e5 80 [2] da 9c }

  condition:
    any of them
}