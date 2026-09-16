rule TTP_XOR_WriteProcessMemory_ae91 {
  strings:
    $key_ae91 = { f9 e3 [2] cb c1 [2] cd f4 [2] e3 f4 [2] dc e8 }

  condition:
    any of them
}