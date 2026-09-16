rule TTP_XOR_WriteProcessMemory_a84d {
  strings:
    $key_a84d = { ff 3f [2] cd 1d [2] cb 28 [2] e5 28 [2] da 34 }

  condition:
    any of them
}