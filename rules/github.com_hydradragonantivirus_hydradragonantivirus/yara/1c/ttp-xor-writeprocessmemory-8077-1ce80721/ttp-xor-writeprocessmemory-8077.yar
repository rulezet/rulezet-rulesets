rule TTP_XOR_WriteProcessMemory_8077 {
  strings:
    $key_8077 = { d7 05 [2] e5 27 [2] e3 12 [2] cd 12 [2] f2 0e }

  condition:
    any of them
}