rule TTP_XOR_WriteProcessMemory_8010 {
  strings:
    $key_8010 = { d7 62 [2] e5 40 [2] e3 75 [2] cd 75 [2] f2 69 }

  condition:
    any of them
}