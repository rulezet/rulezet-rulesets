rule TTP_XOR_WriteProcessMemory_e1a9 {
  strings:
    $key_e1a9 = { b6 db [2] 84 f9 [2] 82 cc [2] ac cc [2] 93 d0 }

  condition:
    any of them
}