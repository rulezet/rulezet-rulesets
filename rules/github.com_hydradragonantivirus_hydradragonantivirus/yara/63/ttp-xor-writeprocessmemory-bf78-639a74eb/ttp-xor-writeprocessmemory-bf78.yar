rule TTP_XOR_WriteProcessMemory_bf78 {
  strings:
    $key_bf78 = { e8 0a [2] da 28 [2] dc 1d [2] f2 1d [2] cd 01 }

  condition:
    any of them
}