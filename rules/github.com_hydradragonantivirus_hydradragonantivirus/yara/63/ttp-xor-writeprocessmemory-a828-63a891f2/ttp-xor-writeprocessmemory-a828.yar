rule TTP_XOR_WriteProcessMemory_a828 {
  strings:
    $key_a828 = { ff 5a [2] cd 78 [2] cb 4d [2] e5 4d [2] da 51 }

  condition:
    any of them
}