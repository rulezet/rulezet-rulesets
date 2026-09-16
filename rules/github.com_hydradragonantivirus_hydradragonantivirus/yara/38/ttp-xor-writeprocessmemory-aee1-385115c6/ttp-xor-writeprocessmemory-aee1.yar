rule TTP_XOR_WriteProcessMemory_aee1 {
  strings:
    $key_aee1 = { f9 93 [2] cb b1 [2] cd 84 [2] e3 84 [2] dc 98 }

  condition:
    any of them
}