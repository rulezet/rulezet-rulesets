rule TTP_XOR_WriteProcessMemory_c2a9 {
  strings:
    $key_c2a9 = { 95 db [2] a7 f9 [2] a1 cc [2] 8f cc [2] b0 d0 }

  condition:
    any of them
}