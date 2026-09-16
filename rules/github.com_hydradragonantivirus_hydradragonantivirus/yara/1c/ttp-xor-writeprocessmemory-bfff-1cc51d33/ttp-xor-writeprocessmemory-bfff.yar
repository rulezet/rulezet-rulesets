rule TTP_XOR_WriteProcessMemory_bfff {
  strings:
    $key_bfff = { e8 8d [2] da af [2] dc 9a [2] f2 9a [2] cd 86 }

  condition:
    any of them
}