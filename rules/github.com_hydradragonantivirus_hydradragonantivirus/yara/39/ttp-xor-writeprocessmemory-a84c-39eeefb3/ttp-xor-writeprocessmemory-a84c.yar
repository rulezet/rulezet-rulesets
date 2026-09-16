rule TTP_XOR_WriteProcessMemory_a84c {
  strings:
    $key_a84c = { ff 3e [2] cd 1c [2] cb 29 [2] e5 29 [2] da 35 }

  condition:
    any of them
}