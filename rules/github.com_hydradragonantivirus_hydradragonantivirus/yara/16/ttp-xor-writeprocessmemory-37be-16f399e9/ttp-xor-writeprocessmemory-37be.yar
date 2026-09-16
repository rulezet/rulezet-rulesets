rule TTP_XOR_WriteProcessMemory_37be {
  strings:
    $key_37be = { 60 cc [2] 52 ee [2] 54 db [2] 7a db [2] 45 c7 }

  condition:
    any of them
}