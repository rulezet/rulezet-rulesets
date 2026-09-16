rule TTP_XOR_WriteProcessMemory_a858 {
  strings:
    $key_a858 = { ff 2a [2] cd 08 [2] cb 3d [2] e5 3d [2] da 21 }

  condition:
    any of them
}