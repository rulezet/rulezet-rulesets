rule TTP_XOR_WriteProcessMemory_c5b0 {
  strings:
    $key_c5b0 = { 92 c2 [2] a0 e0 [2] a6 d5 [2] 88 d5 [2] b7 c9 }

  condition:
    any of them
}