rule TTP_XOR_WriteProcessMemory_35a9 {
  strings:
    $key_35a9 = { 62 db [2] 50 f9 [2] 56 cc [2] 78 cc [2] 47 d0 }

  condition:
    any of them
}