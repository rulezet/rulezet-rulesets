rule TTP_XOR_WriteProcessMemory_c2d2 {
  strings:
    $key_c2d2 = { 95 a0 [2] a7 82 [2] a1 b7 [2] 8f b7 [2] b0 ab }

  condition:
    any of them
}