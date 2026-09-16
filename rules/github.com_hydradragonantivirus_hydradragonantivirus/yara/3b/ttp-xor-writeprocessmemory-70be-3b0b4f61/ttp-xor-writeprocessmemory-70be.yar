rule TTP_XOR_WriteProcessMemory_70be {
  strings:
    $key_70be = { 27 cc [2] 15 ee [2] 13 db [2] 3d db [2] 02 c7 }

  condition:
    any of them
}