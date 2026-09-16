rule TTP_XOR_WriteProcessMemory_91be {
  strings:
    $key_91be = { c6 cc [2] f4 ee [2] f2 db [2] dc db [2] e3 c7 }

  condition:
    any of them
}