rule TTP_XOR_WriteProcessMemory_a80c {
  strings:
    $key_a80c = { ff 7e [2] cd 5c [2] cb 69 [2] e5 69 [2] da 75 }

  condition:
    any of them
}