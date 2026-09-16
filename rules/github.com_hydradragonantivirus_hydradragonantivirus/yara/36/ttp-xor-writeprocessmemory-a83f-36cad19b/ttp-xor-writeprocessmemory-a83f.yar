rule TTP_XOR_WriteProcessMemory_a83f {
  strings:
    $key_a83f = { ff 4d [2] cd 6f [2] cb 5a [2] e5 5a [2] da 46 }

  condition:
    any of them
}