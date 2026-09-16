rule TTP_XOR_WriteProcessMemory_bf43 {
  strings:
    $key_bf43 = { e8 31 [2] da 13 [2] dc 26 [2] f2 26 [2] cd 3a }

  condition:
    any of them
}