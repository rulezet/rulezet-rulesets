rule TTP_XOR_WriteProcessMemory_91a9 {
  strings:
    $key_91a9 = { c6 db [2] f4 f9 [2] f2 cc [2] dc cc [2] e3 d0 }

  condition:
    any of them
}