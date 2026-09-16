rule TTP_XOR_WriteProcessMemory_aed1 {
  strings:
    $key_aed1 = { f9 a3 [2] cb 81 [2] cd b4 [2] e3 b4 [2] dc a8 }

  condition:
    any of them
}