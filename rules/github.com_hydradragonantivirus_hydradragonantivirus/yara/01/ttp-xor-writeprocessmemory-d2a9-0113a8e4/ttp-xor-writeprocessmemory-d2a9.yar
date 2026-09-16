rule TTP_XOR_WriteProcessMemory_d2a9 {
  strings:
    $key_d2a9 = { 85 db [2] b7 f9 [2] b1 cc [2] 9f cc [2] a0 d0 }

  condition:
    any of them
}