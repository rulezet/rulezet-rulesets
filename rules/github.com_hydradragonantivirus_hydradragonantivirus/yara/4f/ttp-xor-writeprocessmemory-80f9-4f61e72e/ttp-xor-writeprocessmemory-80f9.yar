rule TTP_XOR_WriteProcessMemory_80f9 {
  strings:
    $key_80f9 = { d7 8b [2] e5 a9 [2] e3 9c [2] cd 9c [2] f2 80 }

  condition:
    any of them
}