rule TTP_XOR_WriteProcessMemory_40be {
  strings:
    $key_40be = { 17 cc [2] 25 ee [2] 23 db [2] 0d db [2] 32 c7 }

  condition:
    any of them
}