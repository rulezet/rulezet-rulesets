rule TTP_XOR_WriteProcessMemory_a85e {
  strings:
    $key_a85e = { ff 2c [2] cd 0e [2] cb 3b [2] e5 3b [2] da 27 }

  condition:
    any of them
}