rule TTP_XOR_WriteProcessMemory_a877 {
  strings:
    $key_a877 = { ff 05 [2] cd 27 [2] cb 12 [2] e5 12 [2] da 0e }

  condition:
    any of them
}