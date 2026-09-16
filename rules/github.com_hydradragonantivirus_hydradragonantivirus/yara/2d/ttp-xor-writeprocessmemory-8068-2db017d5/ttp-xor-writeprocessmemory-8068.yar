rule TTP_XOR_WriteProcessMemory_8068 {
  strings:
    $key_8068 = { d7 1a [2] e5 38 [2] e3 0d [2] cd 0d [2] f2 11 }

  condition:
    any of them
}