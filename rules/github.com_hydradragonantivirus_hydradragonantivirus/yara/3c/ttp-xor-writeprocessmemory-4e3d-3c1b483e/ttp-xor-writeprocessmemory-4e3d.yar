rule TTP_XOR_WriteProcessMemory_4e3d {
  strings:
    $key_4e3d = { 19 4f [2] 2b 6d [2] 2d 58 [2] 03 58 [2] 3c 44 }

  condition:
    any of them
}