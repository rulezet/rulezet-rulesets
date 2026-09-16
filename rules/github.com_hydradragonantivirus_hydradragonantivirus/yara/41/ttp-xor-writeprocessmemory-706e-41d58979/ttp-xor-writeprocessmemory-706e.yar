rule TTP_XOR_WriteProcessMemory_706e {
  strings:
    $key_706e = { 27 1c [2] 15 3e [2] 13 0b [2] 3d 0b [2] 02 17 }

  condition:
    any of them
}