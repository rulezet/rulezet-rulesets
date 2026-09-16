rule TTP_XOR_WriteProcessMemory_d2be {
  strings:
    $key_d2be = { 85 cc [2] b7 ee [2] b1 db [2] 9f db [2] a0 c7 }

  condition:
    any of them
}