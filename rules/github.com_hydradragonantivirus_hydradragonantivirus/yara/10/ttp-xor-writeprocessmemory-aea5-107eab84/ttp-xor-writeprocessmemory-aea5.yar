rule TTP_XOR_WriteProcessMemory_aea5 {
  strings:
    $key_aea5 = { f9 d7 [2] cb f5 [2] cd c0 [2] e3 c0 [2] dc dc }

  condition:
    any of them
}