rule TTP_XOR_WriteProcessMemory_76be {
  strings:
    $key_76be = { 21 cc [2] 13 ee [2] 15 db [2] 3b db [2] 04 c7 }

  condition:
    any of them
}