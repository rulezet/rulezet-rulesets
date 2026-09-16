rule TTP_XOR_WriteProcessMemory_a827 {
  strings:
    $key_a827 = { ff 55 [2] cd 77 [2] cb 42 [2] e5 42 [2] da 5e }

  condition:
    any of them
}