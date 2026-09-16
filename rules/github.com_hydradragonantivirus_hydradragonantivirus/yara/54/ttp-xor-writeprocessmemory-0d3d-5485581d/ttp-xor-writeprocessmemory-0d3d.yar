rule TTP_XOR_WriteProcessMemory_0d3d {
  strings:
    $key_0d3d = { 5a 4f [2] 68 6d [2] 6e 58 [2] 40 58 [2] 7f 44 }

  condition:
    any of them
}