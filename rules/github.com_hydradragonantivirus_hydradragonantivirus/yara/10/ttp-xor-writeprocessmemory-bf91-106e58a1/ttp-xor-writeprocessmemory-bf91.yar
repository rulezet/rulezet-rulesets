rule TTP_XOR_WriteProcessMemory_bf91 {
  strings:
    $key_bf91 = { e8 e3 [2] da c1 [2] dc f4 [2] f2 f4 [2] cd e8 }

  condition:
    any of them
}