rule TTP_XOR_WriteProcessMemory_c6be {
  strings:
    $key_c6be = { 91 cc [2] a3 ee [2] a5 db [2] 8b db [2] b4 c7 }

  condition:
    any of them
}