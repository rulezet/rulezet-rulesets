rule TTP_XOR_WriteProcessMemory_bf7d {
  strings:
    $key_bf7d = { e8 0f [2] da 2d [2] dc 18 [2] f2 18 [2] cd 04 }

  condition:
    any of them
}