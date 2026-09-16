rule TTP_XOR_WriteProcessMemory_bf5e {
  strings:
    $key_bf5e = { e8 2c [2] da 0e [2] dc 3b [2] f2 3b [2] cd 27 }

  condition:
    any of them
}