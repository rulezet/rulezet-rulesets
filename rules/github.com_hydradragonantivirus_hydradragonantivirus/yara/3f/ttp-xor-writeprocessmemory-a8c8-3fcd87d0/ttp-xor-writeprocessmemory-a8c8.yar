rule TTP_XOR_WriteProcessMemory_a8c8 {
  strings:
    $key_a8c8 = { ff ba [2] cd 98 [2] cb ad [2] e5 ad [2] da b1 }

  condition:
    any of them
}