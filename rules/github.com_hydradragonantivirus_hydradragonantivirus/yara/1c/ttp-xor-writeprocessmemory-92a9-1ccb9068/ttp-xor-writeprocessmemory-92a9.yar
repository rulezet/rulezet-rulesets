rule TTP_XOR_WriteProcessMemory_92a9 {
  strings:
    $key_92a9 = { c5 db [2] f7 f9 [2] f1 cc [2] df cc [2] e0 d0 }

  condition:
    any of them
}