rule TTP_XOR_WriteProcessMemory_2d3d {
  strings:
    $key_2d3d = { 7a 4f [2] 48 6d [2] 4e 58 [2] 60 58 [2] 5f 44 }

  condition:
    any of them
}