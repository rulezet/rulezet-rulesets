rule TTP_XOR_WriteProcessMemory_aed9 {
  strings:
    $key_aed9 = { f9 ab [2] cb 89 [2] cd bc [2] e3 bc [2] dc a0 }

  condition:
    any of them
}