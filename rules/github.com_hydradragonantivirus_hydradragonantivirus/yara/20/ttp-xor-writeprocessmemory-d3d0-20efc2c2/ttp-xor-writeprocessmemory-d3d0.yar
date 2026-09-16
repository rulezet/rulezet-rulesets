rule TTP_XOR_WriteProcessMemory_d3d0 {
  strings:
    $key_d3d0 = { 84 a2 [2] b6 80 [2] b0 b5 [2] 9e b5 [2] a1 a9 }

  condition:
    any of them
}