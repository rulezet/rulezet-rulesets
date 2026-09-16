rule TTP_XOR_WriteProcessMemory_d6be {
  strings:
    $key_d6be = { 81 cc [2] b3 ee [2] b5 db [2] 9b db [2] a4 c7 }

  condition:
    any of them
}