rule TTP_XOR_WriteProcessMemory_c3be {
  strings:
    $key_c3be = { 94 cc [2] a6 ee [2] a0 db [2] 8e db [2] b1 c7 }

  condition:
    any of them
}