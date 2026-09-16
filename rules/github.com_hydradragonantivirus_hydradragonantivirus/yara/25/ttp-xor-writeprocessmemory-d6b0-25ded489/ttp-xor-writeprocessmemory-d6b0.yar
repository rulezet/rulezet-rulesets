rule TTP_XOR_WriteProcessMemory_d6b0 {
  strings:
    $key_d6b0 = { 81 c2 [2] b3 e0 [2] b5 d5 [2] 9b d5 [2] a4 c9 }

  condition:
    any of them
}