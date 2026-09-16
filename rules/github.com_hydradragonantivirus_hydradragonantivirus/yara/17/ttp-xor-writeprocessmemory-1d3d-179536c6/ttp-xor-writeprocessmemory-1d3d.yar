rule TTP_XOR_WriteProcessMemory_1d3d {
  strings:
    $key_1d3d = { 4a 4f [2] 78 6d [2] 7e 58 [2] 50 58 [2] 6f 44 }

  condition:
    any of them
}