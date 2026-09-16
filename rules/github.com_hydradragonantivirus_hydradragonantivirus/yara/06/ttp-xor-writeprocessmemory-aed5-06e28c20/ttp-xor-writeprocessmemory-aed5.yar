rule TTP_XOR_WriteProcessMemory_aed5 {
  strings:
    $key_aed5 = { f9 a7 [2] cb 85 [2] cd b0 [2] e3 b0 [2] dc ac }

  condition:
    any of them
}