rule TTP_XOR_WriteProcessMemory_bf49 {
  strings:
    $key_bf49 = { e8 3b [2] da 19 [2] dc 2c [2] f2 2c [2] cd 30 }

  condition:
    any of them
}