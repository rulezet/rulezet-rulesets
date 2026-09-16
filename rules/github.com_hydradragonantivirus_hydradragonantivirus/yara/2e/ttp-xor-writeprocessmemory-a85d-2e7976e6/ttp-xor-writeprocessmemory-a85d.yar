rule TTP_XOR_WriteProcessMemory_a85d {
  strings:
    $key_a85d = { ff 2f [2] cd 0d [2] cb 38 [2] e5 38 [2] da 24 }

  condition:
    any of them
}