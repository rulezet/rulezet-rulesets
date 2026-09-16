rule TTP_XOR_WriteProcessMemory_d3d1 {
  strings:
    $key_d3d1 = { 84 a3 [2] b6 81 [2] b0 b4 [2] 9e b4 [2] a1 a8 }

  condition:
    any of them
}