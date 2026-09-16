rule TTP_XOR_WriteProcessMemory_bf4d {
  strings:
    $key_bf4d = { e8 3f [2] da 1d [2] dc 28 [2] f2 28 [2] cd 34 }

  condition:
    any of them
}