rule TTP_XOR_WriteProcessMemory_a80a {
  strings:
    $key_a80a = { ff 78 [2] cd 5a [2] cb 6f [2] e5 6f [2] da 73 }

  condition:
    any of them
}