rule TTP_XOR_WriteProcessMemory_c2c5 {
  strings:
    $key_c2c5 = { 95 b7 [2] a7 95 [2] a1 a0 [2] 8f a0 [2] b0 bc }

  condition:
    any of them
}