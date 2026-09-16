rule TTP_XOR_WriteProcessMemory_800c {
  strings:
    $key_800c = { d7 7e [2] e5 5c [2] e3 69 [2] cd 69 [2] f2 75 }

  condition:
    any of them
}