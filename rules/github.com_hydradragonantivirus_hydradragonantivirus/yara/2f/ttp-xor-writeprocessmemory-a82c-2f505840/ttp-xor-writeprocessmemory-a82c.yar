rule TTP_XOR_WriteProcessMemory_a82c {
  strings:
    $key_a82c = { ff 5e [2] cd 7c [2] cb 49 [2] e5 49 [2] da 55 }

  condition:
    any of them
}