rule TTP_XOR_WriteProcessMemory_83a9 {
  strings:
    $key_83a9 = { d4 db [2] e6 f9 [2] e0 cc [2] ce cc [2] f1 d0 }

  condition:
    any of them
}