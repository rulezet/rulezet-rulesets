rule TTP_XOR_WriteProcessMemory_d2d4 {
  strings:
    $key_d2d4 = { 85 a6 [2] b7 84 [2] b1 b1 [2] 9f b1 [2] a0 ad }

  condition:
    any of them
}