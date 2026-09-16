rule TTP_XOR_WriteProcessMemory_bf56 {
  strings:
    $key_bf56 = { e8 24 [2] da 06 [2] dc 33 [2] f2 33 [2] cd 2f }

  condition:
    any of them
}