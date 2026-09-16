rule TTP_XOR_WriteProcessMemory_a807 {
  strings:
    $key_a807 = { ff 75 [2] cd 57 [2] cb 62 [2] e5 62 [2] da 7e }

  condition:
    any of them
}