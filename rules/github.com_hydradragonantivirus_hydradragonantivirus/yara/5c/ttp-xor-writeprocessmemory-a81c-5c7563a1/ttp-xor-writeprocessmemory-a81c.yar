rule TTP_XOR_WriteProcessMemory_a81c {
  strings:
    $key_a81c = { ff 6e [2] cd 4c [2] cb 79 [2] e5 79 [2] da 65 }

  condition:
    any of them
}