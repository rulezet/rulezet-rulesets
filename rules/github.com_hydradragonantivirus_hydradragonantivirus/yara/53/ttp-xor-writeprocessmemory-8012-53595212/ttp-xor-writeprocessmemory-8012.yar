rule TTP_XOR_WriteProcessMemory_8012 {
  strings:
    $key_8012 = { d7 60 [2] e5 42 [2] e3 77 [2] cd 77 [2] f2 6b }

  condition:
    any of them
}