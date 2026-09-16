rule TTP_XOR_WriteProcessMemory_c2d1 {
  strings:
    $key_c2d1 = { 95 a3 [2] a7 81 [2] a1 b4 [2] 8f b4 [2] b0 a8 }

  condition:
    any of them
}