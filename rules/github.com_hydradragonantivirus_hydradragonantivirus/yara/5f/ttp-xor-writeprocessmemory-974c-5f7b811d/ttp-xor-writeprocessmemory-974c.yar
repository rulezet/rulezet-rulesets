rule TTP_XOR_WriteProcessMemory_974c {
  strings:
    $key_974c = { c0 3e [2] f2 1c [2] f4 29 [2] da 29 [2] e5 35 }

  condition:
    any of them
}