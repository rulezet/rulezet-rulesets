rule TTP_XOR_WriteProcessMemory_bf36 {
  strings:
    $key_bf36 = { e8 44 [2] da 66 [2] dc 53 [2] f2 53 [2] cd 4f }

  condition:
    any of them
}