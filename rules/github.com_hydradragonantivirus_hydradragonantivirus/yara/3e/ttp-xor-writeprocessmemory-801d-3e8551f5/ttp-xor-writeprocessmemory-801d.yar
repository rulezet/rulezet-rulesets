rule TTP_XOR_WriteProcessMemory_801d {
  strings:
    $key_801d = { d7 6f [2] e5 4d [2] e3 78 [2] cd 78 [2] f2 64 }

  condition:
    any of them
}