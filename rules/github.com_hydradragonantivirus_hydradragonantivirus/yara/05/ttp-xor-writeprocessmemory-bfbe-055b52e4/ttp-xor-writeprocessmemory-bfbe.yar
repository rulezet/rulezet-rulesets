rule TTP_XOR_WriteProcessMemory_bfbe {
  strings:
    $key_bfbe = { e8 cc [2] da ee [2] dc db [2] f2 db [2] cd c7 }

  condition:
    any of them
}