rule TTP_XOR_WriteProcessMemory_3d3d {
  strings:
    $key_3d3d = { 6a 4f [2] 58 6d [2] 5e 58 [2] 70 58 [2] 4f 44 }

  condition:
    any of them
}