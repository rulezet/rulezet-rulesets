rule TTP_XOR_WriteProcessMemory_a8b8 {
  strings:
    $key_a8b8 = { ff ca [2] cd e8 [2] cb dd [2] e5 dd [2] da c1 }

  condition:
    any of them
}