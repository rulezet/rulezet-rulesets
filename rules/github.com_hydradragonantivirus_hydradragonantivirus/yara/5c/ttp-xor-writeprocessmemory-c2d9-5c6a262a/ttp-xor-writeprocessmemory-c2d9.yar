rule TTP_XOR_WriteProcessMemory_c2d9 {
  strings:
    $key_c2d9 = { 95 ab [2] a7 89 [2] a1 bc [2] 8f bc [2] b0 a0 }

  condition:
    any of them
}