rule TTP_XOR_WriteProcessMemory_bffe {
  strings:
    $key_bffe = { e8 8c [2] da ae [2] dc 9b [2] f2 9b [2] cd 87 }

  condition:
    any of them
}