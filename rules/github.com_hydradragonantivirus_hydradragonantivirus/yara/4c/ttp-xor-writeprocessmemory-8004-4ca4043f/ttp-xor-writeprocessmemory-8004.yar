rule TTP_XOR_WriteProcessMemory_8004 {
  strings:
    $key_8004 = { d7 76 [2] e5 54 [2] e3 61 [2] cd 61 [2] f2 7d }

  condition:
    any of them
}