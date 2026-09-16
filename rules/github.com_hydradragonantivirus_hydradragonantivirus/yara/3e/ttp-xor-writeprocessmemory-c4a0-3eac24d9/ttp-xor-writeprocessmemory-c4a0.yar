rule TTP_XOR_WriteProcessMemory_c4a0 {
  strings:
    $key_c4a0 = { 93 d2 [2] a1 f0 [2] a7 c5 [2] 89 c5 [2] b6 d9 }

  condition:
    any of them
}