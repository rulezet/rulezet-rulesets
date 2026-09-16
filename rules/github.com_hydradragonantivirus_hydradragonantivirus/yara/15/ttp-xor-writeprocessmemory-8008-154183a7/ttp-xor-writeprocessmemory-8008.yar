rule TTP_XOR_WriteProcessMemory_8008 {
  strings:
    $key_8008 = { d7 7a [2] e5 58 [2] e3 6d [2] cd 6d [2] f2 71 }

  condition:
    any of them
}