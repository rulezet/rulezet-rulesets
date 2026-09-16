rule TTP_XOR_WriteProcessMemory_d2d5 {
  strings:
    $key_d2d5 = { 85 a7 [2] b7 85 [2] b1 b0 [2] 9f b0 [2] a0 ac }

  condition:
    any of them
}