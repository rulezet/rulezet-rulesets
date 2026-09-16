rule TTP_XOR_WriteProcessMemory_a869 {
  strings:
    $key_a869 = { ff 1b [2] cd 39 [2] cb 0c [2] e5 0c [2] da 10 }

  condition:
    any of them
}