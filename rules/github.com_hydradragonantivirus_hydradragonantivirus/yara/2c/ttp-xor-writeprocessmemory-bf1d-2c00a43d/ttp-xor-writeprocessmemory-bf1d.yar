rule TTP_XOR_WriteProcessMemory_bf1d {
  strings:
    $key_bf1d = { e8 6f [2] da 4d [2] dc 78 [2] f2 78 [2] cd 64 }

  condition:
    any of them
}