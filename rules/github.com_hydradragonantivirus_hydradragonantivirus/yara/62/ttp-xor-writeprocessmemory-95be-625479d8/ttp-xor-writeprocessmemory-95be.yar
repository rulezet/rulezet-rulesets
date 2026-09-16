rule TTP_XOR_WriteProcessMemory_95be {
  strings:
    $key_95be = { c2 cc [2] f0 ee [2] f6 db [2] d8 db [2] e7 c7 }

  condition:
    any of them
}