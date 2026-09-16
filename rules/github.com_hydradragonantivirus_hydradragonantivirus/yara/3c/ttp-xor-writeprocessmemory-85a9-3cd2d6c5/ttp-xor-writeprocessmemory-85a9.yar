rule TTP_XOR_WriteProcessMemory_85a9 {
  strings:
    $key_85a9 = { d2 db [2] e0 f9 [2] e6 cc [2] c8 cc [2] f7 d0 }

  condition:
    any of them
}