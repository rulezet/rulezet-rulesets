rule TTP_XOR_WriteProcessMemory_92be {
  strings:
    $key_92be = { c5 cc [2] f7 ee [2] f1 db [2] df db [2] e0 c7 }

  condition:
    any of them
}