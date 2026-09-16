rule TTP_XOR_WriteProcessMemory_bf2d {
  strings:
    $key_bf2d = { e8 5f [2] da 7d [2] dc 48 [2] f2 48 [2] cd 54 }

  condition:
    any of them
}