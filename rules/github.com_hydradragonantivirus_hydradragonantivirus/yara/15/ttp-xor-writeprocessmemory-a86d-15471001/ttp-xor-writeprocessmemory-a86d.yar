rule TTP_XOR_WriteProcessMemory_a86d {
  strings:
    $key_a86d = { ff 1f [2] cd 3d [2] cb 08 [2] e5 08 [2] da 14 }

  condition:
    any of them
}