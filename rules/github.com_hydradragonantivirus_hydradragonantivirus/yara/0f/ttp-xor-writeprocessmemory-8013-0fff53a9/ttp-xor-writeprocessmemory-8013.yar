rule TTP_XOR_WriteProcessMemory_8013 {
  strings:
    $key_8013 = { d7 61 [2] e5 43 [2] e3 76 [2] cd 76 [2] f2 6a }

  condition:
    any of them
}