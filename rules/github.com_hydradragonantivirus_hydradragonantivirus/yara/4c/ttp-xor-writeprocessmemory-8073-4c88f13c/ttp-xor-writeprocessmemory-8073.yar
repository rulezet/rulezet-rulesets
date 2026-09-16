rule TTP_XOR_WriteProcessMemory_8073 {
  strings:
    $key_8073 = { d7 01 [2] e5 23 [2] e3 16 [2] cd 16 [2] f2 0a }

  condition:
    any of them
}