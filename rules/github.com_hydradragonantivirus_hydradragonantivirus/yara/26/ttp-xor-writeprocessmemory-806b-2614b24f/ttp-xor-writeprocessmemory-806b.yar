rule TTP_XOR_WriteProcessMemory_806b {
  strings:
    $key_806b = { d7 19 [2] e5 3b [2] e3 0e [2] cd 0e [2] f2 12 }

  condition:
    any of them
}