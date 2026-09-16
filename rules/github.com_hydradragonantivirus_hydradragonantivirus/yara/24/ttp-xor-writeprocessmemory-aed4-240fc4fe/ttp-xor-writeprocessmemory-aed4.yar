rule TTP_XOR_WriteProcessMemory_aed4 {
  strings:
    $key_aed4 = { f9 a6 [2] cb 84 [2] cd b1 [2] e3 b1 [2] dc ad }

  condition:
    any of them
}