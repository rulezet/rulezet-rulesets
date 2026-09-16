rule TTP_XOR_WriteProcessMemory_97be {
  strings:
    $key_97be = { c0 cc [2] f2 ee [2] f4 db [2] da db [2] e5 c7 }

  condition:
    any of them
}