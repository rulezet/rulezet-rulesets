rule TTP_XOR_WriteProcessMemory_c3c0 {
  strings:
    $key_c3c0 = { 94 b2 [2] a6 90 [2] a0 a5 [2] 8e a5 [2] b1 b9 }

  condition:
    any of them
}