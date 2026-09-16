rule TTP_XOR_WriteProcessMemory_82be {
  strings:
    $key_82be = { d5 cc [2] e7 ee [2] e1 db [2] cf db [2] f0 c7 }

  condition:
    any of them
}