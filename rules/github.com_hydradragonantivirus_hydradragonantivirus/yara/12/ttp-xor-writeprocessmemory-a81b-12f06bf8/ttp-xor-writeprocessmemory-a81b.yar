rule TTP_XOR_WriteProcessMemory_a81b {
  strings:
    $key_a81b = { ff 69 [2] cd 4b [2] cb 7e [2] e5 7e [2] da 62 }

  condition:
    any of them
}