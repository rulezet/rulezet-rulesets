rule TTP_XOR_WriteProcessMemory_16be {
  strings:
    $key_16be = { 41 cc [2] 73 ee [2] 75 db [2] 5b db [2] 64 c7 }

  condition:
    any of them
}