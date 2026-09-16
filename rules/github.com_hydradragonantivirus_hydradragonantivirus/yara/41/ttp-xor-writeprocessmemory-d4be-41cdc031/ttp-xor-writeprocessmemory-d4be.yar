rule TTP_XOR_WriteProcessMemory_d4be {
  strings:
    $key_d4be = { 83 cc [2] b1 ee [2] b7 db [2] 99 db [2] a6 c7 }

  condition:
    any of them
}