rule TTP_XOR_WriteProcessMemory_bf69 {
  strings:
    $key_bf69 = { e8 1b [2] da 39 [2] dc 0c [2] f2 0c [2] cd 10 }

  condition:
    any of them
}