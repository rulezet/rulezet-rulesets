rule TTP_XOR_WriteProcessMemory_c0be {
  strings:
    $key_c0be = { 97 cc [2] a5 ee [2] a3 db [2] 8d db [2] b2 c7 }

  condition:
    any of them
}