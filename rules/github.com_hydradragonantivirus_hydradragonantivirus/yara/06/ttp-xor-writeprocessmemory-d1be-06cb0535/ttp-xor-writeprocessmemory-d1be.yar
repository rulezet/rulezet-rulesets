rule TTP_XOR_WriteProcessMemory_d1be {
  strings:
    $key_d1be = { 86 cc [2] b4 ee [2] b2 db [2] 9c db [2] a3 c7 }

  condition:
    any of them
}