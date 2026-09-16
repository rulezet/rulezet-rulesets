rule TTP_XOR_WriteProcessMemory_a8ca {
  strings:
    $key_a8ca = { ff b8 [2] cd 9a [2] cb af [2] e5 af [2] da b3 }

  condition:
    any of them
}