rule TTP_XOR_WriteProcessMemory_bf41 {
  strings:
    $key_bf41 = { e8 33 [2] da 11 [2] dc 24 [2] f2 24 [2] cd 38 }

  condition:
    any of them
}