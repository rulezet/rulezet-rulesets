rule TTP_XOR_WriteProcessMemory_d3d4 {
  strings:
    $key_d3d4 = { 84 a6 [2] b6 84 [2] b0 b1 [2] 9e b1 [2] a1 ad }

  condition:
    any of them
}