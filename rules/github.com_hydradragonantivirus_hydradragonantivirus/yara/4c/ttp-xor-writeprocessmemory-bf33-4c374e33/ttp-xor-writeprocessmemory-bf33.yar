rule TTP_XOR_WriteProcessMemory_bf33 {
  strings:
    $key_bf33 = { e8 41 [2] da 63 [2] dc 56 [2] f2 56 [2] cd 4a }

  condition:
    any of them
}