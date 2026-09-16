rule TTP_XOR_WriteProcessMemory_a85b {
  strings:
    $key_a85b = { ff 29 [2] cd 0b [2] cb 3e [2] e5 3e [2] da 22 }

  condition:
    any of them
}