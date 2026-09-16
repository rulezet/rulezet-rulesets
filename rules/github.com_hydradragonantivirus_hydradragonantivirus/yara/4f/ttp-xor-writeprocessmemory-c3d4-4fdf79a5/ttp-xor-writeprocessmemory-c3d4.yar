rule TTP_XOR_WriteProcessMemory_c3d4 {
  strings:
    $key_c3d4 = { 94 a6 [2] a6 84 [2] a0 b1 [2] 8e b1 [2] b1 ad }

  condition:
    any of them
}