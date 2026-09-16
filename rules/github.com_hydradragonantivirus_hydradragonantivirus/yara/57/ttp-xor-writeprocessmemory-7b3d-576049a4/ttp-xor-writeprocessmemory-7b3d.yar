rule TTP_XOR_WriteProcessMemory_7b3d {
  strings:
    $key_7b3d = { 2c 4f [2] 1e 6d [2] 18 58 [2] 36 58 [2] 09 44 }

  condition:
    any of them
}