rule TTP_XOR_WriteProcessMemory_97a9 {
  strings:
    $key_97a9 = { c0 db [2] f2 f9 [2] f4 cc [2] da cc [2] e5 d0 }

  condition:
    any of them
}