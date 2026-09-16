rule TTP_XOR_WriteProcessMemory_8019 {
  strings:
    $key_8019 = { d7 6b [2] e5 49 [2] e3 7c [2] cd 7c [2] f2 60 }

  condition:
    any of them
}