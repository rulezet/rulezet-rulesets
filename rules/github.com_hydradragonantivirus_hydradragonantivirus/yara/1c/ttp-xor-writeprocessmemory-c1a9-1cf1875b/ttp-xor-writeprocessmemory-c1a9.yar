rule TTP_XOR_WriteProcessMemory_c1a9 {
  strings:
    $key_c1a9 = { 96 db [2] a4 f9 [2] a2 cc [2] 8c cc [2] b3 d0 }

  condition:
    any of them
}