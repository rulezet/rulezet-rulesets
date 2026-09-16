rule TTP_XOR_WriteProcessMemory_a84e {
  strings:
    $key_a84e = { ff 3c [2] cd 1e [2] cb 2b [2] e5 2b [2] da 37 }

  condition:
    any of them
}