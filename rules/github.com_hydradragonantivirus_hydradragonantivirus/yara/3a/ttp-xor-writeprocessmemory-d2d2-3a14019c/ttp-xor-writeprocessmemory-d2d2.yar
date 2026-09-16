rule TTP_XOR_WriteProcessMemory_d2d2 {
  strings:
    $key_d2d2 = { 85 a0 [2] b7 82 [2] b1 b7 [2] 9f b7 [2] a0 ab }

  condition:
    any of them
}