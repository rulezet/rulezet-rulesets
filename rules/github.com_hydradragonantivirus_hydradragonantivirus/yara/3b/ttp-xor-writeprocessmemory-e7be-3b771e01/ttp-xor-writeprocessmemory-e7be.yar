rule TTP_XOR_WriteProcessMemory_e7be {
  strings:
    $key_e7be = { b0 cc [2] 82 ee [2] 84 db [2] aa db [2] 95 c7 }

  condition:
    any of them
}