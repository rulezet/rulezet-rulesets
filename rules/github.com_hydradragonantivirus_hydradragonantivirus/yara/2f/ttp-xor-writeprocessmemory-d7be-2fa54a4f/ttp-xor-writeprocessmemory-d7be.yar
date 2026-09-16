rule TTP_XOR_WriteProcessMemory_d7be {
  strings:
    $key_d7be = { 80 cc [2] b2 ee [2] b4 db [2] 9a db [2] a5 c7 }

  condition:
    any of them
}