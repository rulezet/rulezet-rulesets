rule TTP_XOR_WriteProcessMemory_e1be {
  strings:
    $key_e1be = { b6 cc [2] 84 ee [2] 82 db [2] ac db [2] 93 c7 }

  condition:
    any of them
}