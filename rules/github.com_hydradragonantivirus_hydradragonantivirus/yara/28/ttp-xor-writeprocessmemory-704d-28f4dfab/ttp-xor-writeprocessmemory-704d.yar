rule TTP_XOR_WriteProcessMemory_704d {
  strings:
    $key_704d = { 27 3f [2] 15 1d [2] 13 28 [2] 3d 28 [2] 02 34 }

  condition:
    any of them
}