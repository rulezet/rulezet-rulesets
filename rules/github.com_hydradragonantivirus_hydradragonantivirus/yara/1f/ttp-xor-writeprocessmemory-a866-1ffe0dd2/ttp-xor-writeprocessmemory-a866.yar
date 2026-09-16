rule TTP_XOR_WriteProcessMemory_a866 {
  strings:
    $key_a866 = { ff 14 [2] cd 36 [2] cb 03 [2] e5 03 [2] da 1f }

  condition:
    any of them
}