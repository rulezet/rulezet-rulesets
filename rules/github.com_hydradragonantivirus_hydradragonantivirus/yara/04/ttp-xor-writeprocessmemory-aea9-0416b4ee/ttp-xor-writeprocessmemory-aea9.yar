rule TTP_XOR_WriteProcessMemory_aea9 {
  strings:
    $key_aea9 = { f9 db [2] cb f9 [2] cd cc [2] e3 cc [2] dc d0 }

  condition:
    any of them
}