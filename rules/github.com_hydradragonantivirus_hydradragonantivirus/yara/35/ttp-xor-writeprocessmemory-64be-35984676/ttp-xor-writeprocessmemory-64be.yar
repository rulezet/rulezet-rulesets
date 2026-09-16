rule TTP_XOR_WriteProcessMemory_64be {
  strings:
    $key_64be = { 33 cc [2] 01 ee [2] 07 db [2] 29 db [2] 16 c7 }

  condition:
    any of them
}