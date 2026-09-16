rule TTP_XOR_WriteProcessMemory_8029 {
  strings:
    $key_8029 = { d7 5b [2] e5 79 [2] e3 4c [2] cd 4c [2] f2 50 }

  condition:
    any of them
}