rule TTP_XOR_WriteProcessMemory_87a9 {
  strings:
    $key_87a9 = { d0 db [2] e2 f9 [2] e4 cc [2] ca cc [2] f5 d0 }

  condition:
    any of them
}