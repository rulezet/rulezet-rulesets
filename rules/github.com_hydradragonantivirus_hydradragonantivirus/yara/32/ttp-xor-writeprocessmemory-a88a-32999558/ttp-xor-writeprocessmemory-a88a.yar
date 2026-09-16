rule TTP_XOR_WriteProcessMemory_a88a {
  strings:
    $key_a88a = { ff f8 [2] cd da [2] cb ef [2] e5 ef [2] da f3 }

  condition:
    any of them
}