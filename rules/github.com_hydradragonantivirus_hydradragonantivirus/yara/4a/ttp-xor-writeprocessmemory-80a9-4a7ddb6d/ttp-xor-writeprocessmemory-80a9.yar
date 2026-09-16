rule TTP_XOR_WriteProcessMemory_80a9 {
  strings:
    $key_80a9 = { d7 db [2] e5 f9 [2] e3 cc [2] cd cc [2] f2 d0 }

  condition:
    any of them
}