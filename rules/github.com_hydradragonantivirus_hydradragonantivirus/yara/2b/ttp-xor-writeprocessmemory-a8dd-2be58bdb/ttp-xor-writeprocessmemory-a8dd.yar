rule TTP_XOR_WriteProcessMemory_a8dd {
  strings:
    $key_a8dd = { ff af [2] cd 8d [2] cb b8 [2] e5 b8 [2] da a4 }

  condition:
    any of them
}