rule TTP_XOR_WriteProcessMemory_bfed {
  strings:
    $key_bfed = { e8 9f [2] da bd [2] dc 88 [2] f2 88 [2] cd 94 }

  condition:
    any of them
}