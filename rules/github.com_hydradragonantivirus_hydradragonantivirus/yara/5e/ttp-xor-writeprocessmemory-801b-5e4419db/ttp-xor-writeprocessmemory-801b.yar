rule TTP_XOR_WriteProcessMemory_801b {
  strings:
    $key_801b = { d7 69 [2] e5 4b [2] e3 7e [2] cd 7e [2] f2 62 }

  condition:
    any of them
}