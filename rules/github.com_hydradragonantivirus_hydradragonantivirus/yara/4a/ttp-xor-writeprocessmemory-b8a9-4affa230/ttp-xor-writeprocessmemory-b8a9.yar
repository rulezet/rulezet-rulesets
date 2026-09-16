rule TTP_XOR_WriteProcessMemory_b8a9 {
  strings:
    $key_b8a9 = { ef db [2] dd f9 [2] db cc [2] f5 cc [2] ca d0 }

  condition:
    any of them
}