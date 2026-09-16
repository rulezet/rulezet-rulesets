rule TTP_XOR_WriteProcessMemory_bfbd {
  strings:
    $key_bfbd = { e8 cf [2] da ed [2] dc d8 [2] f2 d8 [2] cd c4 }

  condition:
    any of them
}