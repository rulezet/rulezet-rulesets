rule TTP_XOR_WriteProcessMemory_85be {
  strings:
    $key_85be = { d2 cc [2] e0 ee [2] e6 db [2] c8 db [2] f7 c7 }

  condition:
    any of them
}