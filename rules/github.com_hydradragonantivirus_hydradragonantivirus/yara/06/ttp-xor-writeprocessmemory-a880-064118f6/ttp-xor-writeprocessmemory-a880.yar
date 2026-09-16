rule TTP_XOR_WriteProcessMemory_a880 {
  strings:
    $key_a880 = { ff f2 [2] cd d0 [2] cb e5 [2] e5 e5 [2] da f9 }

  condition:
    any of them
}