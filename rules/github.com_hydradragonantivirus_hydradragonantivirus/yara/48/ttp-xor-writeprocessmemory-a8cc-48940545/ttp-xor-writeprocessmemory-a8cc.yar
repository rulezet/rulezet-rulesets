rule TTP_XOR_WriteProcessMemory_a8cc {
  strings:
    $key_a8cc = { ff be [2] cd 9c [2] cb a9 [2] e5 a9 [2] da b5 }

  condition:
    any of them
}