rule TTP_XOR_WriteProcessMemory_c2d5 {
  strings:
    $key_c2d5 = { 95 a7 [2] a7 85 [2] a1 b0 [2] 8f b0 [2] b0 ac }

  condition:
    any of them
}