rule TTP_XOR_WriteProcessMemory_d5b1 {
  strings:
    $key_d5b1 = { 82 c3 [2] b0 e1 [2] b6 d4 [2] 98 d4 [2] a7 c8 }

  condition:
    any of them
}