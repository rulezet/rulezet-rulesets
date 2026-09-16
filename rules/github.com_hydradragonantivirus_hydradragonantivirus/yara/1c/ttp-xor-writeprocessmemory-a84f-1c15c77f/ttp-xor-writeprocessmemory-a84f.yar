rule TTP_XOR_WriteProcessMemory_a84f {
  strings:
    $key_a84f = { ff 3d [2] cd 1f [2] cb 2a [2] e5 2a [2] da 36 }

  condition:
    any of them
}