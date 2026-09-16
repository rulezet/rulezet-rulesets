rule TTP_XOR_WriteProcessMemory_3d3f {
  strings:
    $key_3d3f = { 6a 4d [2] 58 6f [2] 5e 5a [2] 70 5a [2] 4f 46 }

  condition:
    any of them
}