rule TTP_XOR_WriteProcessMemory_bf40 {
  strings:
    $key_bf40 = { e8 32 [2] da 10 [2] dc 25 [2] f2 25 [2] cd 39 }

  condition:
    any of them
}