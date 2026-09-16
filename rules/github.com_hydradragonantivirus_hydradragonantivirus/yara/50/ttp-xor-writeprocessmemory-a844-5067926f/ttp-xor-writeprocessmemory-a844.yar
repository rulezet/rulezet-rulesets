rule TTP_XOR_WriteProcessMemory_a844 {
  strings:
    $key_a844 = { ff 36 [2] cd 14 [2] cb 21 [2] e5 21 [2] da 3d }

  condition:
    any of them
}