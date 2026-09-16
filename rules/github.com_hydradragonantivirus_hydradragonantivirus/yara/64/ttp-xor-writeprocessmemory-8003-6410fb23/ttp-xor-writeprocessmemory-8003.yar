rule TTP_XOR_WriteProcessMemory_8003 {
  strings:
    $key_8003 = { d7 71 [2] e5 53 [2] e3 66 [2] cd 66 [2] f2 7a }

  condition:
    any of them
}