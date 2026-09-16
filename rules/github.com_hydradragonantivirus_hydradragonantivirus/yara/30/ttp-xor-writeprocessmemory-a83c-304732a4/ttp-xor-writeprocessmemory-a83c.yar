rule TTP_XOR_WriteProcessMemory_a83c {
  strings:
    $key_a83c = { ff 4e [2] cd 6c [2] cb 59 [2] e5 59 [2] da 45 }

  condition:
    any of them
}