rule TTP_XOR_WriteProcessMemory_aed6 {
  strings:
    $key_aed6 = { f9 a4 [2] cb 86 [2] cd b3 [2] e3 b3 [2] dc af }

  condition:
    any of them
}