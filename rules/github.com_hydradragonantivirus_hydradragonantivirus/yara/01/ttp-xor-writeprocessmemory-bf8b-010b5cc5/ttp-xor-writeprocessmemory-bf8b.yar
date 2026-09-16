rule TTP_XOR_WriteProcessMemory_bf8b {
  strings:
    $key_bf8b = { e8 f9 [2] da db [2] dc ee [2] f2 ee [2] cd f2 }

  condition:
    any of them
}