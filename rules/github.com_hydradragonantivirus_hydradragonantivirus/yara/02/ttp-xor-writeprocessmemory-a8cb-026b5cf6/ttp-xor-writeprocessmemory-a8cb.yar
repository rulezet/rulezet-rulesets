rule TTP_XOR_WriteProcessMemory_a8cb {
  strings:
    $key_a8cb = { ff b9 [2] cd 9b [2] cb ae [2] e5 ae [2] da b2 }

  condition:
    any of them
}