rule TTP_XOR_WriteProcessMemory_a89a {
  strings:
    $key_a89a = { ff e8 [2] cd ca [2] cb ff [2] e5 ff [2] da e3 }

  condition:
    any of them
}