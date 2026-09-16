rule TTP_XOR_WriteProcessMemory_bf60 {
  strings:
    $key_bf60 = { e8 12 [2] da 30 [2] dc 05 [2] f2 05 [2] cd 19 }

  condition:
    any of them
}