rule TTP_XOR_WriteProcessMemory_802c {
  strings:
    $key_802c = { d7 5e [2] e5 7c [2] e3 49 [2] cd 49 [2] f2 55 }

  condition:
    any of them
}