rule TTP_XOR_WriteProcessMemory_a80e {
  strings:
    $key_a80e = { ff 7c [2] cd 5e [2] cb 6b [2] e5 6b [2] da 77 }

  condition:
    any of them
}