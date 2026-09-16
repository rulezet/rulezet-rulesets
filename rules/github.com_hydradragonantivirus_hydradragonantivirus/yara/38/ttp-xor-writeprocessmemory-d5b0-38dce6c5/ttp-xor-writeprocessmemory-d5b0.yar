rule TTP_XOR_WriteProcessMemory_d5b0 {
  strings:
    $key_d5b0 = { 82 c2 [2] b0 e0 [2] b6 d5 [2] 98 d5 [2] a7 c9 }

  condition:
    any of them
}