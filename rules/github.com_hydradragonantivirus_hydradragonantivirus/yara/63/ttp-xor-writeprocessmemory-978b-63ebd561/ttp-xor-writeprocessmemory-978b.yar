rule TTP_XOR_WriteProcessMemory_978b {
  strings:
    $key_978b = { c0 f9 [2] f2 db [2] f4 ee [2] da ee [2] e5 f2 }

  condition:
    any of them
}