rule TTP_XOR_WriteProcessMemory_6f3d {
  strings:
    $key_6f3d = { 38 4f [2] 0a 6d [2] 0c 58 [2] 22 58 [2] 1d 44 }

  condition:
    any of them
}