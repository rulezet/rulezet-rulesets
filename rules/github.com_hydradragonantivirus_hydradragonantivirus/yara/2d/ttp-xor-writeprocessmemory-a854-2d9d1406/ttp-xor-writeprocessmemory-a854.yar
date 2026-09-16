rule TTP_XOR_WriteProcessMemory_a854 {
  strings:
    $key_a854 = { ff 26 [2] cd 04 [2] cb 31 [2] e5 31 [2] da 2d }

  condition:
    any of them
}