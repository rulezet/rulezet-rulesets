rule TTP_XOR_WriteProcessMemory_bf08 {
  strings:
    $key_bf08 = { e8 7a [2] da 58 [2] dc 6d [2] f2 6d [2] cd 71 }

  condition:
    any of them
}