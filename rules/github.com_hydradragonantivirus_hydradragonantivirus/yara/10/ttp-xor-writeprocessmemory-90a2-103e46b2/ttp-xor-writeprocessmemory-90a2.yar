rule TTP_XOR_WriteProcessMemory_90a2 {
  strings:
    $key_90a2 = { c7 d0 [2] f5 f2 [2] f3 c7 [2] dd c7 [2] e2 db }

  condition:
    any of them
}