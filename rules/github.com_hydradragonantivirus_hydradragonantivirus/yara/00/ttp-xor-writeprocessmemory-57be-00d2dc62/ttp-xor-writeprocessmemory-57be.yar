rule TTP_XOR_WriteProcessMemory_57be {
  strings:
    $key_57be = { 00 cc [2] 32 ee [2] 34 db [2] 1a db [2] 25 c7 }

  condition:
    any of them
}