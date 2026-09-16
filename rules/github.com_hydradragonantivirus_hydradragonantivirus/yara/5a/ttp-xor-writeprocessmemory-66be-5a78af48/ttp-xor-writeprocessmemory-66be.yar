rule TTP_XOR_WriteProcessMemory_66be {
  strings:
    $key_66be = { 31 cc [2] 03 ee [2] 05 db [2] 2b db [2] 14 c7 }

  condition:
    any of them
}