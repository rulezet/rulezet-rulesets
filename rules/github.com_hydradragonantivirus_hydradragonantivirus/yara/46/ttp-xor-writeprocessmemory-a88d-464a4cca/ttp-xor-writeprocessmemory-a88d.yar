rule TTP_XOR_WriteProcessMemory_a88d {
  strings:
    $key_a88d = { ff ff [2] cd dd [2] cb e8 [2] e5 e8 [2] da f4 }

  condition:
    any of them
}