rule TTP_XOR_WriteProcessMemory_c2c0 {
  strings:
    $key_c2c0 = { 95 b2 [2] a7 90 [2] a1 a5 [2] 8f a5 [2] b0 b9 }

  condition:
    any of them
}