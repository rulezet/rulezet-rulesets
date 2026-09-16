rule TTP_XOR_WriteProcessMemory_bf30 {
  strings:
    $key_bf30 = { e8 42 [2] da 60 [2] dc 55 [2] f2 55 [2] cd 49 }

  condition:
    any of them
}