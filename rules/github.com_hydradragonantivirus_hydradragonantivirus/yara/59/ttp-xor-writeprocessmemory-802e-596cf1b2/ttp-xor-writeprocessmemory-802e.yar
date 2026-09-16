rule TTP_XOR_WriteProcessMemory_802e {
  strings:
    $key_802e = { d7 5c [2] e5 7e [2] e3 4b [2] cd 4b [2] f2 57 }

  condition:
    any of them
}