rule TTP_XOR_WriteProcessMemory_c2b1 {
  strings:
    $key_c2b1 = { 95 c3 [2] a7 e1 [2] a1 d4 [2] 8f d4 [2] b0 c8 }

  condition:
    any of them
}