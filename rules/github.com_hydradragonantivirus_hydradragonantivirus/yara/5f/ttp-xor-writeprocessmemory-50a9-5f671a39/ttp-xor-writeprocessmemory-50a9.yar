rule TTP_XOR_WriteProcessMemory_50a9 {
  strings:
    $key_50a9 = { 07 db [2] 35 f9 [2] 33 cc [2] 1d cc [2] 22 d0 }

  condition:
    any of them
}