rule TTP_XOR_WriteProcessMemory_c5b1 {
  strings:
    $key_c5b1 = { 92 c3 [2] a0 e1 [2] a6 d4 [2] 88 d4 [2] b7 c8 }

  condition:
    any of them
}