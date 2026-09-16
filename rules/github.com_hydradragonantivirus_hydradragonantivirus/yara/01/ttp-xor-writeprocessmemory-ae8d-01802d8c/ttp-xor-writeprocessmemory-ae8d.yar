rule TTP_XOR_WriteProcessMemory_ae8d {
  strings:
    $key_ae8d = { f9 ff [2] cb dd [2] cd e8 [2] e3 e8 [2] dc f4 }

  condition:
    any of them
}