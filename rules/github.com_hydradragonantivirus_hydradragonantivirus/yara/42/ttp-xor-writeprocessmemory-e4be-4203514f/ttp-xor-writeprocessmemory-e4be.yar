rule TTP_XOR_WriteProcessMemory_e4be {
  strings:
    $key_e4be = { b3 cc [2] 81 ee [2] 87 db [2] a9 db [2] 96 c7 }

  condition:
    any of them
}