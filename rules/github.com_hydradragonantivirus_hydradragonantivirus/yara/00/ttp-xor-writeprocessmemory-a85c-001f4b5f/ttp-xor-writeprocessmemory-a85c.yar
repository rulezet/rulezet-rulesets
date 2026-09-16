rule TTP_XOR_WriteProcessMemory_a85c {
  strings:
    $key_a85c = { ff 2e [2] cd 0c [2] cb 39 [2] e5 39 [2] da 25 }

  condition:
    any of them
}