rule TTP_XOR_WriteProcessMemory_77a9 {
  strings:
    $key_77a9 = { 20 db [2] 12 f9 [2] 14 cc [2] 3a cc [2] 05 d0 }

  condition:
    any of them
}