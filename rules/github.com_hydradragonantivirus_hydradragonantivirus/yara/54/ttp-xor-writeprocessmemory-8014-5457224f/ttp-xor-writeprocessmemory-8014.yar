rule TTP_XOR_WriteProcessMemory_8014 {
  strings:
    $key_8014 = { d7 66 [2] e5 44 [2] e3 71 [2] cd 71 [2] f2 6d }

  condition:
    any of them
}