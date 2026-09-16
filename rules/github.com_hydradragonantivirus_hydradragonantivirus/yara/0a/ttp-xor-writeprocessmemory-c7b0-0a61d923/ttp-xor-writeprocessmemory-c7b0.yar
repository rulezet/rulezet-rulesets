rule TTP_XOR_WriteProcessMemory_c7b0 {
  strings:
    $key_c7b0 = { 90 c2 [2] a2 e0 [2] a4 d5 [2] 8a d5 [2] b5 c9 }

  condition:
    any of them
}