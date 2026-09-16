rule TTP_XOR_WriteProcessMemory_704e {
  strings:
    $key_704e = { 27 3c [2] 15 1e [2] 13 2b [2] 3d 2b [2] 02 37 }

  condition:
    any of them
}