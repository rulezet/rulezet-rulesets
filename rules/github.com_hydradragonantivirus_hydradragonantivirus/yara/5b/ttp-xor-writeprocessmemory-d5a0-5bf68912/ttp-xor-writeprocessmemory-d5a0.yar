rule TTP_XOR_WriteProcessMemory_d5a0 {
  strings:
    $key_d5a0 = { 82 d2 [2] b0 f0 [2] b6 c5 [2] 98 c5 [2] a7 d9 }

  condition:
    any of them
}