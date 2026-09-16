rule TTP_XOR_WriteProcessMemory_c4b0 {
  strings:
    $key_c4b0 = { 93 c2 [2] a1 e0 [2] a7 d5 [2] 89 d5 [2] b6 c9 }

  condition:
    any of them
}