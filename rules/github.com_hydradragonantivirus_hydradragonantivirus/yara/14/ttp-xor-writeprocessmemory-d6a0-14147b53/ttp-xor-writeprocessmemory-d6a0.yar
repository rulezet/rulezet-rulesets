rule TTP_XOR_WriteProcessMemory_d6a0 {
  strings:
    $key_d6a0 = { 81 d2 [2] b3 f0 [2] b5 c5 [2] 9b c5 [2] a4 d9 }

  condition:
    any of them
}