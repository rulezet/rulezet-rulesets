rule TTP_XOR_WriteProcessMemory_60be {
  strings:
    $key_60be = { 37 cc [2] 05 ee [2] 03 db [2] 2d db [2] 12 c7 }

  condition:
    any of them
}