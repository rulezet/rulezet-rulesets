rule TTP_XOR_WriteProcessMemory_7008 {
  strings:
    $key_7008 = { 27 7a [2] 15 58 [2] 13 6d [2] 3d 6d [2] 02 71 }

  condition:
    any of them
}