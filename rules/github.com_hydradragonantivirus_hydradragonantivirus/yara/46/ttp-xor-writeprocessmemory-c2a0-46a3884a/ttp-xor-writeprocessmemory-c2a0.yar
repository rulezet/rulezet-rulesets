rule TTP_XOR_WriteProcessMemory_c2a0 {
  strings:
    $key_c2a0 = { 95 d2 [2] a7 f0 [2] a1 c5 [2] 8f c5 [2] b0 d9 }

  condition:
    any of them
}