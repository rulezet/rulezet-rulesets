rule TTP_XOR_WriteProcessMemory_03be {
  strings:
    $key_03be = { 54 cc [2] 66 ee [2] 60 db [2] 4e db [2] 71 c7 }

  condition:
    any of them
}