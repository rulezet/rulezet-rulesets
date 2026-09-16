rule TTP_XOR_WriteProcessMemory_65a9 {
  strings:
    $key_65a9 = { 32 db [2] 00 f9 [2] 06 cc [2] 28 cc [2] 17 d0 }

  condition:
    any of them
}