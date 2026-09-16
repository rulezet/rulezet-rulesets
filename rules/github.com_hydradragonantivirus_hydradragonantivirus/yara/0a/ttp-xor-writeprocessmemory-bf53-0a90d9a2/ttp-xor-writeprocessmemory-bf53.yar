rule TTP_XOR_WriteProcessMemory_bf53 {
  strings:
    $key_bf53 = { e8 21 [2] da 03 [2] dc 36 [2] f2 36 [2] cd 2a }

  condition:
    any of them
}