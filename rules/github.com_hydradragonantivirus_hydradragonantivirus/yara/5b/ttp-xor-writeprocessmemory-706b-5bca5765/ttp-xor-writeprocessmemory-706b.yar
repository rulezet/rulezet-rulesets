rule TTP_XOR_WriteProcessMemory_706b {
  strings:
    $key_706b = { 27 19 [2] 15 3b [2] 13 0e [2] 3d 0e [2] 02 12 }

  condition:
    any of them
}