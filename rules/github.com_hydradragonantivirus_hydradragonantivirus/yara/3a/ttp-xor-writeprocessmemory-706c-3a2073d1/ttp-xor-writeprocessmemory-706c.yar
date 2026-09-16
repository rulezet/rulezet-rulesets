rule TTP_XOR_WriteProcessMemory_706c {
  strings:
    $key_706c = { 27 1e [2] 15 3c [2] 13 09 [2] 3d 09 [2] 02 15 }

  condition:
    any of them
}