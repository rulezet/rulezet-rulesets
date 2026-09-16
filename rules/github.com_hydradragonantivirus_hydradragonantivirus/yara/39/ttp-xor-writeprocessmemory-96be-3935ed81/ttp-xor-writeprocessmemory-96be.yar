rule TTP_XOR_WriteProcessMemory_96be {
  strings:
    $key_96be = { c1 cc [2] f3 ee [2] f5 db [2] db db [2] e4 c7 }

  condition:
    any of them
}