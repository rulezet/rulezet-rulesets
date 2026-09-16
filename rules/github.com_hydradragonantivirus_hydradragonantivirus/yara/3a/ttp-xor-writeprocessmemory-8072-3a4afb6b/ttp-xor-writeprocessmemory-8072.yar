rule TTP_XOR_WriteProcessMemory_8072 {
  strings:
    $key_8072 = { d7 00 [2] e5 22 [2] e3 17 [2] cd 17 [2] f2 0b }

  condition:
    any of them
}