rule TTP_XOR_WriteProcessMemory_70a9 {
  strings:
    $key_70a9 = { 27 db [2] 15 f9 [2] 13 cc [2] 3d cc [2] 02 d0 }

  condition:
    any of them
}