rule TTP_XOR_WriteProcessMemory_ae54 {
  strings:
    $key_ae54 = { f9 26 [2] cb 04 [2] cd 31 [2] e3 31 [2] dc 2d }

  condition:
    any of them
}