rule TTP_XOR_WriteProcessMemory_a81d {
  strings:
    $key_a81d = { ff 6f [2] cd 4d [2] cb 78 [2] e5 78 [2] da 64 }

  condition:
    any of them
}