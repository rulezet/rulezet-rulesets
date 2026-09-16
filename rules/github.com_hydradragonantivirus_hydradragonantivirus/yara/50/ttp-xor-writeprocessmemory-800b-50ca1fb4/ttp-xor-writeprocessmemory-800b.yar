rule TTP_XOR_WriteProcessMemory_800b {
  strings:
    $key_800b = { d7 79 [2] e5 5b [2] e3 6e [2] cd 6e [2] f2 72 }

  condition:
    any of them
}