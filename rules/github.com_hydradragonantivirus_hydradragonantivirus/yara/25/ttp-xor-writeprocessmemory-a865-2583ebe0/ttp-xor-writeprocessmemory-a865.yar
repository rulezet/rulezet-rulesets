rule TTP_XOR_WriteProcessMemory_a865 {
  strings:
    $key_a865 = { ff 17 [2] cd 35 [2] cb 00 [2] e5 00 [2] da 1c }

  condition:
    any of them
}