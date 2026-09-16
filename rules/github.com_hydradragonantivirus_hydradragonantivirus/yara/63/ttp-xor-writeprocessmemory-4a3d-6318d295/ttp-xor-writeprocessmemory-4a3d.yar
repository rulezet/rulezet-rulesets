rule TTP_XOR_WriteProcessMemory_4a3d {
  strings:
    $key_4a3d = { 1d 4f [2] 2f 6d [2] 29 58 [2] 07 58 [2] 38 44 }

  condition:
    any of them
}