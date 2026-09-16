rule TTP_XOR_WriteProcessMemory_aed3 {
  strings:
    $key_aed3 = { f9 a1 [2] cb 83 [2] cd b6 [2] e3 b6 [2] dc aa }

  condition:
    any of them
}