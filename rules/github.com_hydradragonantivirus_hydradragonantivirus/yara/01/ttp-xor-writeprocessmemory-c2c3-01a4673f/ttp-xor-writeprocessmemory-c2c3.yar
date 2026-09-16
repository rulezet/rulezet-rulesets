rule TTP_XOR_WriteProcessMemory_c2c3 {
  strings:
    $key_c2c3 = { 95 b1 [2] a7 93 [2] a1 a6 [2] 8f a6 [2] b0 ba }

  condition:
    any of them
}