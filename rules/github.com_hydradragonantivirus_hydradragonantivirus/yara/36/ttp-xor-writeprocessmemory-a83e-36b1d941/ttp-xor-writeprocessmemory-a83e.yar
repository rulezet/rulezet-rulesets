rule TTP_XOR_WriteProcessMemory_a83e {
  strings:
    $key_a83e = { ff 4c [2] cd 6e [2] cb 5b [2] e5 5b [2] da 47 }

  condition:
    any of them
}