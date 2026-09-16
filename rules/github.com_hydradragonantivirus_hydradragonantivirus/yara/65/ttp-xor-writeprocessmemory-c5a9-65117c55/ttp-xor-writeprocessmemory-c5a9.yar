rule TTP_XOR_WriteProcessMemory_c5a9 {
  strings:
    $key_c5a9 = { 92 db [2] a0 f9 [2] a6 cc [2] 88 cc [2] b7 d0 }

  condition:
    any of them
}