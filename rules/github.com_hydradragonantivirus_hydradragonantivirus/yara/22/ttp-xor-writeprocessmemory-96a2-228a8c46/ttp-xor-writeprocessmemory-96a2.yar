rule TTP_XOR_WriteProcessMemory_96a2 {
  strings:
    $key_96a2 = { c1 d0 [2] f3 f2 [2] f5 c7 [2] db c7 [2] e4 db }

  condition:
    any of them
}