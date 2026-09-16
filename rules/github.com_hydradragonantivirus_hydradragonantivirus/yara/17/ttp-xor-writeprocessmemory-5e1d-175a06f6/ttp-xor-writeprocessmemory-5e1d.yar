rule TTP_XOR_WriteProcessMemory_5e1d {
  strings:
    $key_5e1d = { 09 6f [2] 3b 4d [2] 3d 78 [2] 13 78 [2] 2c 64 }

  condition:
    any of them
}