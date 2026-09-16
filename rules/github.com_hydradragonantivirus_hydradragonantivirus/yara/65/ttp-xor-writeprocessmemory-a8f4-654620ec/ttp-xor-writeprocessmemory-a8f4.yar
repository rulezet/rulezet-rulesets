rule TTP_XOR_WriteProcessMemory_a8f4 {
  strings:
    $key_a8f4 = { ff 86 [2] cd a4 [2] cb 91 [2] e5 91 [2] da 8d }

  condition:
    any of them
}