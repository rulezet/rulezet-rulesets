rule TTP_XOR_WriteProcessMemory_a84a {
  strings:
    $key_a84a = { ff 38 [2] cd 1a [2] cb 2f [2] e5 2f [2] da 33 }

  condition:
    any of them
}