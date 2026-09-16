rule TTP_XOR_WriteProcessMemory_bea9 {
  strings:
    $key_bea9 = { e9 db [2] db f9 [2] dd cc [2] f3 cc [2] cc d0 }

  condition:
    any of them
}