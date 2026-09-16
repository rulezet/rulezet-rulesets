rule TTP_XOR_WriteProcessMemory_bf4b {
  strings:
    $key_bf4b = { e8 39 [2] da 1b [2] dc 2e [2] f2 2e [2] cd 32 }

  condition:
    any of them
}