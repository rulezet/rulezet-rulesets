rule TTP_XOR_WriteProcessMemory_700b {
  strings:
    $key_700b = { 27 79 [2] 15 5b [2] 13 6e [2] 3d 6e [2] 02 72 }

  condition:
    any of them
}