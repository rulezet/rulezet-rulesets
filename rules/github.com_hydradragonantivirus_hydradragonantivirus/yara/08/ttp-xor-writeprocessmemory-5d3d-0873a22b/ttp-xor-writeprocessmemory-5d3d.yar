rule TTP_XOR_WriteProcessMemory_5d3d {
  strings:
    $key_5d3d = { 0a 4f [2] 38 6d [2] 3e 58 [2] 10 58 [2] 2f 44 }

  condition:
    any of them
}